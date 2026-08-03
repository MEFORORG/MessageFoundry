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
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from fastapi import HTTPException, Request, WebSocket, status

from messagefoundry.api.tls_client_cert import MF_CLIENT_PEERCERT_STATE_KEY
from messagefoundry.auth import AuthProvider, Identity, Permission, Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.tls_policy import HopDisposition

# Re-imported, not redefined. The cert->principal mapping now lives in the neutral package-root leaf
# so the inbound connectors' `intake_auth` peer control (ADR 0154 D6) can reach it — this module
# imports fastapi, so `transports/` cannot. Importing it back here keeps this the only definition, so
# the two identity planes cannot drift apart. Re-exported for `tests/test_api_tls.py`, which has
# imported it from this module since ADR 0083.
from messagefoundry.credential import client_cert_principal
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cert_expiry import peer_cert_expiry

log = logging.getLogger(__name__)

# ASVS 6.4.5: fallback sink so a service caller's expiring cert is still visible at WARNING on an
# install with no [alerts] notifier wired. Module-level (not per-request) — it is stateless.
_FALLBACK_ALERT_SINK: AlertSink = LoggingAlertSink()

#: ``path`` reported for a handshake-observed cert: there is no PEM file on this arm (the operator can
#: list one via ``[api].tls_client_cert_files`` for the file-based arm). Not a path — a provenance label.
_HANDSHAKE_CERT_PATH = "(presented at mTLS handshake — no local file)"

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

# ASVS 6.3.3: while a session's second factor is PENDING, only these self-service routes stay
# reachable. Keyed on (METHOD, path), NOT on path alone like the must-change set above: /me/mfa is
# GET (read your factor status — safe while pending) and DELETE (disable your factor — emphatically
# not), and a path-only entry would exempt both. The same trap applies to /me/sessions.
#
# /auth/mfa-verify is HOW a session becomes satisfied, so it must gate itself out; /me/password and
# /me/reauth are the binding deadlock carve-outs (a fresh account can be must_change AND mfa_pending
# in the same instant). Enrollment (POST /me/mfa/enroll, /confirm) is NOT listed because it rides
# require_reauth_only_action, which opts out via mfa_gate=False — an un-enrolled user could never
# satisfy a gate that stands in front of the only route that enrolls them.
#
# Deliberately NOT exempt: GET /me/sessions and GET /me/security-events. A pending session has proven
# ONE factor, which is exactly the attacker-holds-the-password case; handing it the victim's session
# inventory and client-IP history is reconnaissance. ASVS 7.5.2 self-service is a POST-authentication
# clause, and neither route is on any deadlock-escape path (revocation still works: POST /me/reauth
# then DELETE /me/sessions, both reachable).
_MFA_EXEMPT_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/auth/logout"),
        ("GET", "/auth/me"),
        ("POST", "/auth/mfa-verify"),
        ("POST", "/me/password"),
        ("POST", "/me/reauth"),
        ("GET", "/me/mfa"),
    }
)

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
        # Uploaded-logs writes (BACKLOG #125/#126): importing a PHI file at rest and destructively
        # deleting one are both state-changing. FILES_BROWSE is deliberately EXCLUDED (a PHI read with
        # its own upload.browse audit row + step-up, like the MESSAGES_VIEW_* grants above).
        Permission.FILES_UPLOAD,
        Permission.FILES_DELETE,
    }
)


def _grant_audit_permission(
    permissions: tuple[Permission, ...], *, audit_all: bool = False
) -> Permission | None:
    """The permission whose GRANT should be audited (BACKLOG #195a), or ``None`` when none qualifies.

    Default (the shipped 16.3.2 read-polling deviation): the first permission in the sensitive
    ``_GRANT_AUDIT_PERMISSIONS`` set, so only the state-changing / config / user-mgmt surface is audited.
    Under ``audit_all`` (the ``[diagnostics].audit_all_authz`` Posture-B verbosity, BACKLOG #244 / ASVS
    16.3.2): audit EVERY route — the first permission that is **not** a PHI-view grant. PHI-view grants
    (``MESSAGES_VIEW_SUMMARY`` / ``_VIEW_RAW``) stay excluded even under 'all' because the PHI-access
    audit path already records those accesses (avoid double rows). Returning a single permission keeps
    the grant to ONE audit row per request even on a multi-permission route."""
    if audit_all:
        for permission in permissions:
            if permission not in _PHI_VIEW_PERMISSIONS:
                return permission
        return None
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


def _audit_all_authz(app_state: object) -> bool:
    """Whether to audit EVERY authorization grant, not just the sensitive set (ASVS 16.3.2 'all'
    verbosity, ``[diagnostics].audit_all_authz``, BACKLOG #244). Threaded onto ``app.state`` by
    ``create_app``; default off, so the shipped audit-grant behaviour is byte-identical."""
    return bool(getattr(app_state, "audit_all_authz", False))


def bearer_token(request: Request) -> str | None:
    """Extract a ``Bearer`` token from the Authorization header, if present."""
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[len("Bearer ") :].strip() or None
    return None


def client_ip(request: Request) -> str | None:
    """The caller's client address, matching how login records it on the session (``_client`` in
    ``auth_routes``). Used by the WP-L3-13 new-client-IP risk signal so the comparison is
    apples-to-apples, and — since ADR 0150 — as the ``client`` recorded on audit rows. It is public
    (not ``_``-prefixed) precisely so audit callers REUSE this one extraction rather than growing a
    second, divergent notion of "the client address": two extractors would eventually disagree about
    proxy handling and the audit trail would contradict the risk signal.

    Behind a declared trusted proxy this already resolves to the real client:
    uvicorn runs with ``forwarded_allow_ips = settings.api.trusted_proxies`` (``__main__.py``;
    defaults to ``[]`` = trust nothing), and an off-loopback proxied bind is gated to require it. The
    residual is the inherent limit that an in-process per-IP limiter cannot stop pure source-IP
    rotation by a directly-reachable attacker (SEC-024)."""
    return request.client.host if request.client else None


def require(
    *permissions: Permission, mfa_gate: bool = True
) -> Callable[[Request], Awaitable[Identity]]:
    """Build a dependency that authenticates the caller and asserts each of ``permissions``.

    ``mfa_gate=False`` suppresses the ASVS 6.3.3 second-factor ACCESS gate for routes an MFA-pending
    session must still reach. Only the ``*_reauth_only*`` factories pass it, because an un-enrolled
    user cannot satisfy a gate standing in front of the one route that enrolls them.

    The flag lives HERE rather than on a private helper, which was tried and reverted: routing the
    body through ``_require`` renamed the returned closure's ``__qualname__``, and the route-map drift
    guard derives a route's gate from exactly that (``_gate_of`` ignores any qualname not starting
    with ``require``). Every route then read as UNGATED. Widening this signature instead costs one
    ``ENGINE_UI_SEAM`` bump — the mechanism that exists for precisely this — while ``mfa_gate`` is an
    ordinary closure cell the drift guard already ignores."""

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
        # ASVS 6.3.3 — MFA is an ACCESS gate, not only a step-up gate. Ordering is load-bearing in
        # BOTH directions. must_change stays FIRST: a fresh account is must_change AND mfa_pending at
        # the same instant, and GET /me/mfa is MFA-exempt but NOT must-change-exempt, so leading with
        # MFA would point that account at /auth/mfa-verify, which it cannot satisfy until it has
        # rotated — the brick. And this stays ABOVE the permission loop: refusing below it would tell
        # an unverified caller whether it holds the permission, a free authorization oracle.
        if (
            mfa_gate
            and (request.method, request.url.path) not in _MFA_EXEMPT_ROUTES
            and not await auth.mfa_satisfied(bearer_token(request))
        ):
            await auth.audit_mfa_denied(identity, request.url.path)
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "multi-factor verification required; POST /auth/mfa-verify then retry",
                headers={"X-MFA-Required": "1"},
            )
        for permission in permissions:
            if not identity.has(permission):
                await auth.audit_permission_denied(identity, permission, request.url.path)
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, f"missing permission: {permission.value}"
                )
        # BACKLOG #195a (ASVS 16.3.2): record the authorization GRANT. By DEFAULT only the
        # sensitive/state-changing surface on a NON-GET request is audited — the method guard drops the
        # polled GET /approvals (APPROVALS_APPROVE) and the permission set drops every read/monitoring
        # grant (console polling would otherwise flood the audit chain). Under [diagnostics].audit_all_authz
        # (BACKLOG #244, Posture-B verbosity, threaded onto app.state) EVERY satisfied route is audited —
        # including GETs — except the PHI-view grants, still recorded by the PHI-access audit path.
        audit_all = _audit_all_authz(request.app.state)
        if audit_all or request.method != "GET":
            audited = _grant_audit_permission(permissions, audit_all=audit_all)
            if audited is not None:
                await auth.audit_permission_granted(identity, audited, request.url.path)
        return identity

    return dependency


def require_paced(*permissions: Permission) -> Callable[[Request], Awaitable[Identity]]:
    """Like :func:`require`, plus per-actor anti-automation PACING on the state-changing admin
    surface (BACKLOG #193, ASVS 2.4.2) — but WITHOUT the MFA / step-up gates. For the mutating admin
    routes that warrant paced throttling yet not a full step-up re-proof: connection start/stop/
    restart, DR activate/release, approvals approve/reject, alert ack/resolve, statistics reset. A
    non-GET request from an actor over the per-actor rate is refused early with 429 + Retry-After: 1
    (logged, not silent) before the identity is returned. Reuses the SAME #193 limiter as
    :func:`require_step_up` via :func:`_enforce_admin_write_pacing`, so pacing coverage is uniform
    across both gates. The embedding/no-auth path is unaffected (no per-actor identity to key on)."""
    base = require(*permissions)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None and auth.enabled:
            _enforce_admin_write_pacing(request, auth, identity)
        return identity

    return dependency


# --- mTLS client-cert → Identity resolver (#200, ADR 0083) -------------------------------------------
# Beside require(): resolve a VERIFIED client certificate's subject/SAN to a MessageFoundry Identity via
# the [api].tls_client_cert_identities allow-list, so a service-to-service caller can authenticate with a
# pinned mTLS cert instead of a bearer token. DENY-BY-DEFAULT: an unmapped/spoofed subject → no identity.
# This is ADDITIVE and does NOT touch require()/the bearer path — the cert-identity plane is admitted ONLY
# by require_service_cert (below), which is cert-only and PHI-fenced, so it can never bypass the session /
# step-up / MFA controls. Activated by the scope-populating shim in api/tls_client_cert (ADR 0083).


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


def note_client_cert_expiry(request: Request, peercert: Mapping[str, Any], label: str) -> None:
    """Raise a ``cert_expiry`` alert when a **service caller's** verified client cert is expired or within
    ``[cert_monitor].warn_days`` (ASVS 6.4.5).

    The engine never holds these certs as files — it only ever *sees* them at the mTLS handshake — so this
    is the only place a caller's approaching expiry is observable in-flight. An operator who holds copies
    can additionally list them under ``[api].tls_client_cert_files`` for the periodic file monitor, which
    is what covers a caller that has stopped connecting altogether.

    Throttled per ``(label, notAfter)`` at the ``[cert_monitor].check_interval_seconds`` cadence — the
    same rate the file monitor would alert at — because this runs on a per-REQUEST path: without it a
    chatty caller would drive an ``alert_instance`` upsert per request (the durable alert-state write
    happens *before* the sink's own notification throttle). The key space is bounded by the operator's
    ``tls_client_cert_identities`` allow-list, so it cannot be grown by an unmapped caller.

    **Never raises** and never blocks: a monitoring signal must not be able to fail an authentication
    path, so every failure is swallowed and logged. Inert when ``[cert_monitor]`` is absent or
    ``warn_days`` is 0. Carries no key material and no PHI — a label, the ISO expiry and a day count."""
    try:
        state = request.app.state
        settings = getattr(state, "cert_monitor_settings", None)
        if settings is None or settings.warn_days <= 0:
            return  # monitor off / not wired (direct create_app path) — inert
        now = time.time()
        checked = peer_cert_expiry(peercert, now=now)
        if checked is None:
            return  # no parseable notAfter — nothing to say
        not_after_iso, days_remaining = checked
        if days_remaining > settings.warn_days:
            return  # comfortably valid
        # Re-alert throttle keyed on the cert's OWN identity: a renewed cert (new notAfter) alerts
        # immediately rather than inheriting the replaced cert's cooldown.
        seen: dict[tuple[str, str], float] | None = getattr(state, "client_cert_expiry_seen", None)
        if seen is None:
            seen = {}
            state.client_cert_expiry_seen = seen
        key = (label, not_after_iso)
        last = seen.get(key)
        if last is not None and now - last < settings.check_interval_seconds:
            return
        seen[key] = now
        sink: AlertSink = getattr(state, "notifier", None) or _FALLBACK_ALERT_SINK
        sink.cert_expiry(
            label,
            path=_HANDSHAKE_CERT_PATH,
            not_after=not_after_iso,
            days_remaining=days_remaining,
        )
    except Exception:
        # Deliberately broad: this is advisory monitoring hanging off an auth path. Anything unexpected
        # here must degrade to "no alert", never to a failed or delayed authentication.
        log.warning("client-cert expiry check failed for %r", label, exc_info=True)


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
    peer_cert = peer_cert_from_request(request)
    principal = client_cert_principal(peer_cert, cert_map)
    if principal is None:
        return None  # unmapped / spoofed subject → deny-by-default
    # ASVS 6.4.5: the cert is verified AND allow-listed here, so its expiry is worth reporting — and the
    # label space is bounded by the operator's own map. Advisory only: it never gates the resolution.
    if peer_cert is not None:
        note_client_cert_expiry(request, peer_cert, f"api-client:{principal}")
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
        enforce_phi_read_pacing(request, identity)
        return identity

    return dependency


def enforce_phi_read_pacing(request: Request, identity: Identity) -> None:
    """Charge the per-actor PHI-read budget (WP-8, ASVS 2.4.1), raising 429 when it is spent.

    Factored out of :func:`require_phi_read` so the bulk-PHI routes gated by :func:`require_step_up`
    can charge the SAME per-actor bucket. They need it explicitly: ``require_step_up`` paces via
    :func:`_enforce_admin_write_pacing`, which is **NON-GET only**, so a step-up *GET* that selects
    message bodies in bulk (``/messages/search``, ``/messages/export``, ``/search/layered``) would
    otherwise be admitted unpaced — a single authenticated actor could stream far more PHI per minute
    through export than the per-actor budget allows through ``/messages/{id}``.

    Charged at ADMISSION (before selection), so a request that is going to be refused never pays for
    the store work first."""
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


def _enforce_admin_write_pacing(request: Request, auth: AuthService, identity: Identity) -> None:
    """Per-actor anti-automation pacing on the state-changing admin surface (BACKLOG #193, ASVS
    2.4.2). NON-GET only, so a read is never paced; consulted only when auth is enabled (the caller
    guards that). A throttled write is logged (not silent) and refused early with 429 + Retry-After:
    1 BEFORE any further work. Shared by :func:`require_step_up` (the sensitive step-up surface) and
    :func:`require_paced` (the state-changing surface that needs pacing WITHOUT a step-up re-proof),
    so both gates key on the SAME per-actor limiter (one bucket per actor)."""
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
            # surface (NON-GET only), shared with require_paced so both gates draw one per-actor bucket.
            _enforce_admin_write_pacing(request, auth, identity)
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
            new_ip = await auth.flag_new_client_ip(token, client_ip(request), path=request.url.path)
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
    session from silently enrolling an attacker-controlled authenticator (WP-14).

    ``mfa_gate=False`` extends that same deadlock carve-out to the ASVS 6.3.3 ACCESS gate now applied
    by :func:`require`: without it the enrollment routes would sit behind a factor the caller does
    not yet have."""
    base = require(*permissions, mfa_gate=False)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None and auth.enabled:
            token = bearer_token(request)
            # Same new-client-IP contextual-risk layer as require_step_up (WP-L3-13); the MFA gate is
            # intentionally skipped here (enrollment would otherwise deadlock — see the docstring).
            new_ip = await auth.flag_new_client_ip(token, client_ip(request), path=request.url.path)
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
            # NOT redundant with the ASVS 6.3.3 gate in require(), despite covering the same sessions
            # for every non-exempt path. DELETE /me/mfa shares its path with the MFA-exempt
            # GET /me/mfa, so if _MFA_EXEMPT_ROUTES is ever flattened to bare paths this check is the
            # ONLY thing stopping a half-authenticated session from switching its own second factor
            # off. Measured, not assumed: neutering the base gate leaves this route refused. Keep it.
            if not await auth.mfa_satisfied(token):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "multi-factor verification required; POST /auth/mfa-verify then retry",
                    headers={"X-MFA-Required": "1"},
                )
            # `new_ip` is checked first so a short-circuit leaves the single-use grant UNCONSUMED on a
            # forced-step-up (the grant is only popped when we actually reach the action check).
            new_ip = await auth.flag_new_client_ip(token, client_ip(request), path=request.url.path)
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
    window (ADR 0077). Same ``X-Step-Up-Action`` header + org opt-out as :func:`require_step_up_action`.

    Carries the same ``mfa_gate=False`` opt-out as :func:`require_reauth_only`, for the same reason."""
    base = require(*permissions, mfa_gate=False)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None and auth.enabled:
            token = bearer_token(request)
            new_ip = await auth.flag_new_client_ip(token, client_ip(request), path=request.url.path)
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
    not PHI. The ASVS 6.3.3 **MFA access gate is excluded for the same reason, deliberately**: this
    resolver answers tokenless callers by contract, so a second-factor gate here could only ever
    downgrade an already-public answer, never protect anything. Both consumers (``GET /health``,
    ``GET /ai/policy``) are non-PHI."""
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
    # ASVS 6.3.3: an MFA-pending session does not stream either. No exempt set here — every WS route
    # is a data feed, none is part of the enroll/verify escape path. Audited for the same reason as
    # require(): the refusal sits above the permission loop, so nothing else would record it.
    # RESIDUAL: checked once at handshake. A role change that newly puts a live session in scope does
    # not tear down an established socket; the connection's own revalidation is the backstop.
    if not await auth.mfa_satisfied(ws_token(websocket)):
        await auth.audit_mfa_denied(identity, websocket.url.path)
        return None
    for permission in permissions:
        if not identity.has(permission):
            # Audit the denial like the HTTP require() path does, so a revoked/under-privileged
            # user probing the stats feed leaves a trail too (review low-9).
            await auth.audit_permission_denied(identity, permission, websocket.url.path)
            return None
    # BACKLOG #195a (ASVS 16.3.2): audit the grant for the sensitive surface only by default. The shipped
    # stats feed (/ws/stats) requires MONITORING_READ, which is deliberately NOT in
    # _GRANT_AUDIT_PERMISSIONS, so a reconnecting/polling console never floods the audit chain. Under
    # [diagnostics].audit_all_authz (BACKLOG #244) every satisfied WS route is audited (PHI-view still
    # excluded); authorize_ws runs once per connection, not per message, so 'all' cannot flood either.
    audit_all = _audit_all_authz(websocket.app.state)
    audited = _grant_audit_permission(permissions, audit_all=audit_all)
    if audited is not None:
        await auth.audit_permission_granted(identity, audited, websocket.url.path)
    return identity
