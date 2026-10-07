# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""FastAPI authentication + authorization dependencies (deny-by-default).

``require(*permissions)`` is a dependency factory applied to every protected route. Once an
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
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request, Response, WebSocket, WebSocketException, status
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from starlette.requests import HTTPConnection

from messagefoundry.api.tls_client_cert import (
    MF_CLIENT_PEERCERT_STATE_KEY,
    peercert_from_ssl_object,
)
from messagefoundry.auth import AuthProvider, Identity, Permission, Role
from messagefoundry.auth.notifications import deadline_utc as deadline_utc  # re-export
from messagefoundry.auth.service import AuthService, LoginOutcome
from messagefoundry.config.tls_policy import HopDisposition

# Imported, not redefined: the cert->principal matchers live in the neutral package-root leaf, which
# the inbound connectors' `intake_auth` control (ADR 0154 D6) shares. This plane keys by issuer first
# (BACKLOG #2237); the intake plane does not yet.
from messagefoundry.credential import client_cert_principal_under_issuer
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cert_expiry import peer_cert_expiry
from messagefoundry.store.store import UserRecord

log = logging.getLogger(__name__)

# ASVS 6.4.5: fallback sink so an API-side alert (a service caller's expiring cert, an Administrator
# grant) is still visible at WARNING on an install with no [alerts] notifier wired. Module-level (not
# per-request) — it is stateless.
_FALLBACK_ALERT_SINK: AlertSink = LoggingAlertSink()


def alert_sink_for(state: Any) -> AlertSink:
    """The running ``[alerts]`` notifier on ``app.state``, or the logging fallback when none is wired."""
    sink: AlertSink | None = getattr(state, "notifier", None)
    return sink if sink is not None else _FALLBACK_ALERT_SINK


#: ``granted_by`` on the ``administrator_granted`` alert a directory sign-in raises (vault BACKLOG
#: #2610): no administrator acted, the directory's group membership did. It is a fixed marker, styled
#: like the ``<kerberos>`` audit actor. No username check reserves it, so an account literally named
#: ``<directory>`` would read the same in this field; the alert's ``via`` names the route either way.
DIRECTORY_GRANTED_BY = "<directory>"


def alert_administrator_granted(state: Any, key: str, *, via: str, granted_by: str) -> None:
    """Raise the ``administrator_granted`` alert (BACKLOG #315; why, and the key grammar, are on
    ``AlertSink.administrator_granted``). Raised in the API, never from ``auth/`` (CLAUDE.md
    section 4). Best effort: the grant already happened and is audited."""
    try:
        alert_sink_for(state).administrator_granted(key, via=via, granted_by=granted_by)
    except Exception:  # noqa: BLE001 - a sink that breaks its never-raise contract must not 500 a
        # call whose write is already committed and audited.
        log.exception("the administrator_granted alert for %r failed to emit", key)


def alert_directory_administrator_granted(state: Any, outcome: LoginOutcome, *, via: str) -> None:
    """Raise ``administrator_granted`` when a directory sign-in's role sync newly gave the account
    the Administrator role (vault BACKLOG #2610). Every route that completes a directory sign-in
    calls this with its ``outcome`` BEFORE it reads ``ok``, because a refused outcome can still
    carry a grant. ``via`` names the route. A sign-in that gained nothing, or gained only other
    roles, raises nothing."""
    gained = outcome.roles_gained
    if gained is not None and Role.ADMINISTRATOR.value in gained.roles:
        alert_administrator_granted(
            state, f"user:{gained.username}", via=via, granted_by=DIRECTORY_GRANTED_BY
        )


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
# allowed_channels=None is EXPLICIT and load-bearing: the field defaults to the empty set (deny)
# since BACKLOG #1152, and this identity exists precisely to stand in for "authorization is off",
# so it must carry the whole estate rather than inherit the deny-by-default an unprovisioned
# operator gets.
_SYSTEM_IDENTITY = Identity.build(
    user_id="system",
    username="system",
    auth_provider=AuthProvider.LOCAL,
    roles=list(Role),
    allowed_channels=None,
)

# While an account is flagged to rotate its password, only these self-service routes stay reachable.
# /auth/mfa-verify is here for an account that is must-change AND has a factor (admin_reset_password
# keeps factors): /me/password refuses its pending session until the factor is proven (BACKLOG
# #1954), so the factor step has to be reachable or the account can do neither. What it adds for
# every must-change session is that one ceremony: a call draws the sign-in rate budget and, on an
# account with TOTP, a wrong code counts toward the lockout, exactly as it would unconfined.
_MUST_CHANGE_EXEMPT_PATHS = frozenset(
    {"/auth/logout", "/auth/me", "/auth/mfa-verify", "/me/password"}
)

# ADR 0197 Amendment A (N-B2 part 4, AC-A3): the TOTP enrolment path a must-change session reaches
# while its account must enrol a factor with a way past the sign-in lock BEFORE it rotates. Under the
# shipped require_mfa that is every new account. The rotation ends every session, so rotating first
# would pass through "a chosen password, no factor, no session", which anyone who knows the username
# can lock. So the order is enrol, then rotate, and these paths are open to such a session only; for
# every other must-change session the set above stands. Passkey registration is deliberately absent:
# in wave 1 a passkey is not a way past, and the service refuses it as a first factor anyway. Keyed
# on (METHOD, path) for the reason _MFA_EXEMPT_ROUTES gives: GET /me/mfa reads the factor status,
# and DELETE /me/mfa removes a factor, which a path-only entry would open too.
_ENROL_FIRST_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/me/reauth"),
        ("GET", "/me/mfa"),
        ("POST", "/me/mfa/enroll"),
        ("POST", "/me/mfa/confirm"),
    }
)

#: The suffix a must-change refusal carries while the account must enrol first, so a JSON client is
#: told the step it can take. Appended, never prefixed: clients match the refusal's leading text.
_ENROL_FIRST_SUFFIX = "; enrol an authenticator app first"

# ASVS 6.3.3: while a session's second factor is PENDING, only these self-service routes stay
# reachable. Keyed on (METHOD, path), NOT on path alone like the must-change set above: /me/mfa is
# GET (read your factor status — safe while pending) and DELETE (disable your factor — emphatically
# not), and a path-only entry would exempt both. The same trap applies to /me/sessions.
#
# /auth/mfa-verify is HOW a session becomes satisfied, so it must gate itself out; /me/password and
# /me/reauth are the binding deadlock carve-outs (a fresh account can be must_change AND mfa_pending
# in the same instant). /me/password is exempt only for an account with NO factor: see
# _PASSWORD_CHANGE_ROUTE below. Enrollment (POST /me/mfa/enroll, /confirm) is NOT listed
# because it rides require_reauth_only_action, which opts out via mfa_gate=False — an un-enrolled
# user could never satisfy a gate that stands in front of the only route that enrolls them.
#
# Deliberately NOT exempt: GET /me/sessions and GET /me/security-events. A pending session has proven
# ONE factor, which is exactly the attacker-holds-the-password case; handing it the victim's session
# inventory and client-IP history is reconnaissance. ASVS 7.5.2 self-service is a POST-authentication
# clause, and neither route is on any deadlock-escape path (revocation still works: POST /me/reauth
# then DELETE /me/sessions, both reachable).
#
# That revocation path serves an account with NO factor, which has nothing to prove at
# /auth/mfa-verify. An account that HAS one proves it first before that path works (BACKLOG #1951;
# see AuthService._PENDING_REFUSED_ACTIONS). /me/password is limited the same way (#1954).
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

# BACKLOG #1139 (ASVS 6.3.7): while an account has no notification address and a notice channel is
# wired (``Identity.must_set_notify_email``), only these routes stay reachable. Keyed on (METHOD,
# path) for the reason the MFA set above is. /me/notify-email is the way out. The rest are the ways
# out of the two gates that run first, so neither can deadlock behind this one.
#
# THE ``mfa_gate=False`` ROUTES ARE EXEMPT TOO, and they are not listed. Those are the reauth-only
# factories (TOTP enrolment and confirm, session termination): the escapes an account under
# ``require_mfa`` with no factor needs. Keying on the flag rather than on a copy of their paths is
# what keeps this plane and the console's (which exempts every ``allow_mfa_pending`` route) the same.
#
# /me/notify-email is deliberately NOT in the MFA set above. A session still owing its factor has
# proven only the password, and letting that caller choose where the account's notices go would hand
# a password thief the channel meant to warn the holder.
_NOTIFY_EMAIL_EXEMPT_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/auth/logout"),
        ("GET", "/auth/me"),
        ("POST", "/auth/mfa-verify"),
        ("POST", "/me/password"),
        ("POST", "/me/reauth"),
        ("GET", "/me/mfa"),
        ("POST", "/me/notify-email"),
    }
)

#: The 403 detail for a session confined by the set above. Clients match on it, so keep it stable.
NOTIFY_EMAIL_REQUIRED_DETAIL = (
    "notification address required; POST /me/notify-email to set one, then retry"
)

# The one exempt route above whose exemption serves an account with NO factor only. A pending
# session on a non-directory account that HAS one is refused here like anywhere else: a password change
# revokes every session, so without this a caller holding only the password could lock the real
# user out and sign them out everywhere (BACKLOG #1954, ASVS 6.3.3).
# AuthService.password_change_owes_factor decides it; the console's password page asks it too.
_PASSWORD_CHANGE_ROUTE = ("POST", "/me/password")

# BACKLOG #195a (ASVS 16.3.2): the permissions whose authorization GRANT is worth an audit row when the
# trail is NARROWED — the sensitive / state-changing / config / user-mgmt surface.
#
# THIS SET IS NO LONGER THE SHIPPED BEHAVIOUR. BACKLOG #1277 flipped `[diagnostics].audit_all_authz` to
# True, so on the default every grant is recorded and this set is consulted only when an operator sets
# the switch false. It used to be the shipped deviation from "audit every authorization decision", and
# its stated reason — console polling and the /ws/stats feed flooding the hash-chained audit log — named
# a surface that cannot reach here at all. The measurement that establishes that, and what the volume
# actually is, lives once at `config/settings.py` on the `audit_all_authz` field; do not restate it.
#
# The PHI-view grants (MESSAGES_VIEW_SUMMARY / _VIEW_RAW) are excluded under BOTH settings, because the
# PHI-access audit path already records those accesses (dedupe). The set is transport-agnostic so it
# holds identically for HTTP and the WebSocket; while it is in force, a further method != "GET" guard on
# HTTP drops a polled sensitive-permission READ (e.g. GET /approvals, which carries APPROVALS_APPROVE).
_GRANT_AUDIT_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.MESSAGES_REPLAY,
        Permission.MESSAGES_RESEND,
        Permission.MESSAGES_EDIT,
        Permission.MESSAGES_PURGE,
        Permission.CONNECTIONS_CONTROL,
        Permission.CONNECTIONS_TEST,
        Permission.DR_OPERATE,
        Permission.CLUSTER_CONTROL,  # ADR 0056: a planned failover moves the active-passive primary
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
    permissions: tuple[Permission, ...], *, audit_all: bool
) -> Permission | None:
    """The permission whose GRANT should be audited (BACKLOG #195a), or ``None`` when none qualifies.

    ``audit_all`` is REQUIRED rather than defaulted, and that is deliberate as of BACKLOG #1277. A
    default here would be a fifth place carrying a value for one posture, and it would be the one place
    nothing tests: both call sites pass the argument explicitly, so a stale ``= False`` could sit here
    indefinitely and silently hand the narrow, pre-#1277 trail to whatever calls this next.

    Under ``audit_all`` — ``[diagnostics].audit_all_authz``, which is the SHIPPED DEFAULT since BACKLOG
    #1277 — audit every route: the first permission that is **not** a PHI-view grant. With the switch
    off, only the sensitive ``_GRANT_AUDIT_PERMISSIONS`` set is audited (state-changing / config /
    user-mgmt). PHI-view grants (``MESSAGES_VIEW_SUMMARY`` / ``_VIEW_RAW``) stay excluded under BOTH
    settings because the PHI-access audit path already records those accesses (avoid double rows).

    Returning a single permission keeps the grant to ONE audit row per request even on a
    multi-permission route. That ceiling is what bounds the volume the flipped default adds, so it is a
    behavioural contract rather than an optimisation: a caller returning a list would multiply the
    trail by the route's permission count."""
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


def pending_credential_deadline(auth: AuthService, user: UserRecord | None) -> float | None:
    """The instant this account's admin-issued must-change credential stops working, or ``None``.

    BACKLOG #1141 (ASVS 6.4.5). Every route-layer surface that states the deadline of an unclaimed
    credential reads it HERE, so each one states the instant the login gate refuses on. The gate
    refuses when ``must_change_password`` is set and ``now`` is past
    :meth:`AuthService.initial_credential_deadline` of the STORED ``password_changed_at``. This
    mirrors both halves of that test and reads no clock of its own. ``None`` means the gate never
    refuses this credential on time: no such user, a password the holder chose, or
    ``[auth].initial_password_expiry_hours`` set to 0.

    No account is exempt by name. The first-run account named ``admin`` used to get ``None`` here,
    because the WP-3 sweep could retire it before this bound. ADR 0183 retired that account and its
    sweep, so an account an operator names ``admin`` is an ordinary account and gets its deadline.
    """
    if user is None or not user.must_change_password:
        return None
    return auth.initial_credential_deadline(user.password_changed_at)


async def pending_credential_deadline_for(auth: AuthService, user_id: str) -> float | None:
    """:func:`pending_credential_deadline` for an account named by id (one store read)."""
    return pending_credential_deadline(auth, await auth.store.get_user(user_id))


def initial_credential_window_hours(auth: AuthService) -> float | None:
    """How long a newly issued must-change credential lives, in hours, or ``None`` for no expiry.

    For text shown BEFORE the credential exists (the create-user form), when there is no stored stamp
    to anchor an instant to yet. It asks :meth:`AuthService.initial_credential_deadline` for the
    deadline of a credential stamped at the epoch, so the window comes from the same arithmetic the
    gate uses rather than from a second read of the setting.
    """
    deadline = auth.initial_credential_deadline(0.0)
    return None if deadline is None else deadline / 3600.0


def _allow_no_auth(app_state: object) -> bool:
    """Whether this app explicitly opted out of auth (embedding/dev). Default: fail-closed."""
    return bool(getattr(app_state, "allow_no_auth", False))


def _audit_all_authz(app_state: object) -> bool:
    """Whether to audit EVERY authorization grant, not just the sensitive set (ASVS 16.3.2 'all'
    verbosity, ``[diagnostics].audit_all_authz``, BACKLOG #244; ON by default since BACKLOG #1277).

    ``create_app`` always writes the attribute onto ``app.state``, and its own parameter defaults True,
    so every app built through the factory carries the shipped posture. The ``False`` fallback here
    covers only a hand-built ``app.state`` that never went through the factory — a test double or an
    embedder assembling state by hand. It stays False to PRESERVE THE PRIOR BEHAVIOUR of those callers:
    the narrow trail is what a hand-built state got before #1277, and nothing on such a state says its
    author wanted anything else. Both sides are pinned in ``tests/test_auth_hardening.py`` — this
    fallback for a hand-built state, and the wide shipped default through the factory.

    THAT IS A COMPATIBILITY ARGUMENT, NOT A SECURITY ONE, and it is weaker than the reason this
    docstring used to give. The old wording said a wider fallback would be "inventing a grant row for an
    app whose auth wiring is unknown". It would not be: both call sites read this only AFTER
    authorization has already succeeded — in :func:`require` the read sits below the permission loop,
    and :func:`authorize_ws` has the same shape — so a row written here would record a grant that really
    happened, and nothing would be invented. Revisit the argument rather than inherit it if this
    fallback is ever touched (BACKLOG #1421, cost 3)."""
    return bool(getattr(app_state, "audit_all_authz", False))


def bearer_token(request: Request) -> str | None:
    """Extract a ``Bearer`` token from the Authorization header, if present."""
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[len("Bearer ") :].strip() or None
    return None


async def bearer_token_dependency(request: Request) -> str | None:
    """:func:`bearer_token` for use in ``Depends``, so FastAPI calls it on the event loop.

    FastAPI runs a plain ``def`` dependency on an AnyIO worker thread, and that pool is what ASVS
    15.4.4 asks us not to spend on work that never blocks (BACKLOG #2448, a #1195 follow-up).
    :func:`bearer_token` stays sync because engine code calls it directly in many places. Put this
    wrapper in ``Depends``, never the sync function: ``tests/test_thread_pool_fairness_baseline.py``
    fails when a route declares a sync dependency. The wrapper is safe only because the header read
    never blocks. A helper that does block needs a thread, and that test's allow-list says where."""
    return bearer_token(request)


def client_ip(conn: Request | WebSocket) -> str | None:
    """The caller's client address, matching how login records it on the session (``_client`` in
    ``auth_routes``). Used by the WP-L3-13 new-client-IP risk signal so the comparison is
    apples-to-apples, and — since ADR 0150 — as the ``client`` recorded on audit rows. It is public
    (not ``_``-prefixed) precisely so audit callers REUSE this one extraction rather than growing a
    second, divergent notion of "the client address": two extractors would eventually disagree about
    proxy handling and the audit trail would contradict the risk signal.

    **Takes either plane, and that is what the no-second-extractor rule above requires here.**
    :func:`authorize_ws` audits the same three authorization outcomes :func:`require` does, over a
    :class:`WebSocket` rather than a :class:`Request`, so a WS-only extractor is exactly the second
    notion this docstring forbids. Widening costs nothing structural: ``client`` is ONE property on
    starlette's ``HTTPConnection``, which both classes inherit unchanged, so this is the same read on
    both planes rather than two reads that agree today. The parameter is ``conn`` rather than
    ``request`` for the same reason, matching ``_auth.session_cookie_name``.

    Behind a declared trusted proxy this already resolves to the real client:
    uvicorn runs with ``forwarded_allow_ips = settings.api.trusted_proxies`` (``__main__.py``;
    defaults to ``[]`` = trust nothing), and an off-loopback proxied bind is gated to require it. The
    residual is the inherent limit that an in-process per-IP limiter cannot stop pure source-IP
    rotation by a directly-reachable attacker (SEC-024)."""
    return conn.client.host if conn.client else None


def _password_change_required(deadline: float | None, *, suffix: str = "") -> str:
    """The 403 detail for a must-change session, naming the credential's deadline when it has one.

    ``suffix`` names the next step the session can take (the enrol-first step), appended.

    A deadline already passed is stated in the past tense with the one remedy left, and no
    ``suffix``: no step the session takes can revive the credential (BACKLOG #2298). The session
    check ends such a session before this runs, so it is reached only when the deadline passes
    between that check and this read. Strictly after, as the sign-in gate compares."""
    when = None if deadline is None else deadline_utc(deadline)
    if when is None:
        return "password change required" + suffix
    if deadline is not None and time.time() > deadline:
        return (
            f"password change required; the temporary password stopped working at {when};"
            " ask an administrator to reset it"
        )
    return f"password change required; the temporary password stops working at {when}" + suffix


# --- Answering before the request body is read (vault BACKLOG #2739) ---------------------------------
# FastAPI reads and decodes a declared request body BEFORE it solves a route's dependencies, and the
# sign-in check is a dependency. So a gated route that declared a body answered a caller with no
# session from the body parser (422, or 400) and not with the gate's refusal. The owner ruled on
# 2026-10-02 that the refusal comes first.
#
# The mechanism is ONE route class, :class:`AuthenticatedBeforeBodyRoute`, set on the app's router.
# No route opts in and no list names the routes. For a route that declares a body and carries a
# gate it runs, in the order FastAPI would run them, each dependency up to and including the gate
# that is marked as able to answer before the body, and only then lets FastAPI read the body. A
# dependency is marked in one of two ways: :func:`answers_before_body` for a guard that sits ahead
# of a gate, and :func:`_gate` for a ``require*()`` closure, whose step is its AUTHENTICATION step
# alone.
#
# THE GATE ITSELF IS UNCHANGED, AND NOTHING IS HANDED TO IT. After the body is read FastAPI runs the
# gate as the dependency it always was, and the gate resolves the caller again. So a session
# revoked while the body was arriving is refused, as it was before. Handing the gate the identity
# resolved before the body would save that second lookup, and was tried: it let a session revoked
# mid-upload through the routes the factor gate exempts. The second lookup is the price: it reads
# the session, its user and the user's roles, and only a signed-in request to a route with a body
# pays it.
#
# Everything else a gate does still runs once, after the body: must-change, the factor gate, the
# permission loop and its audit rows, pacing and step-up. So a signed-in caller the gate then
# refuses still gets the parser's answer first for a body that does not parse, as before.

#: The function attribute a dependency carries its :class:`BeforeBody` under.
_BEFORE_BODY_ATTR = "__before_body__"

_Gate = Callable[[Request], Awaitable[Identity]]
_Step = Callable[[Request], Awaitable[object]]


@dataclass(frozen=True, slots=True)
class BeforeBody:
    """What one dependency contributes to the check that runs before a request body is read."""

    #: Raises the dependency's own refusal, or returns. Its return value is not used.
    step: _Step
    #: True for a ``require*()`` gate. The early check runs nothing past the first one.
    authenticates: bool


def before_body_of(call: object) -> BeforeBody | None:
    """The :class:`BeforeBody` a dependency was marked with, or ``None`` when it carries none."""
    found = getattr(call, _BEFORE_BODY_ATTR, None)
    return found if isinstance(found, BeforeBody) else None


def answers_before_body[G: _Step](guard: G) -> G:
    """Mark a guard that sits AHEAD of a gate, so the early check runs it first, as FastAPI would.

    For a dependency that only reads ``app.state`` and either returns or raises, such as "no engine
    is attached". The early check calls it and FastAPI then calls it again, so it must have no side
    effect and must give the same answer both times. Without the mark an unauthenticated caller
    would get the gate's refusal where today it gets this guard's, which is a second answer for
    one request shape."""
    setattr(guard, _BEFORE_BODY_ATTR, BeforeBody(guard, authenticates=False))
    return guard


# --- Every route declares its authorization (vault BACKLOG #2604) -----------------------------------
# ``create_app`` installs :func:`refuse_undeclared_route` as an APP-LEVEL dependency, so it runs ahead of
# every route's own dependencies on every route registered on the app. It refuses a matched route
# unless the route DECLARES how it is authorized, in one of two ways:
#
# * a top-level dependency carrying the gate mark, which every ``require*()`` factory here and every
#   ``require_ui*()`` factory in the web console sets through :func:`mark_route_gate`; or
# * an endpoint marked :func:`public_route` with a reason, for the sign-in entry points and the other
#   routes that are anonymous by design. A WebSocket endpoint that authorizes inside its own body is
#   marked :func:`authorizes_in_body` instead, which an HTTP route may not use.
#
# A gate is recognised by its mark, never by its name. The route walk in
# ``scripts/security/route_gates.py`` reads the same mark, so a dependency that is merely NAMED like a
# gate reads as no gate at all, to both.
#
# WHAT IT DOES NOT COVER, at least:
#
# * A route inside a MOUNTED application. A mount carries no dependencies, so the refusal never runs
#   there. ``/ui/static`` is the only mount the engine serves, and a test pins that.
# * A Starlette ``Route`` added outside FastAPI's routing, which also has no dependencies. The only
#   ones are the interactive docs and the schema, which ``expose_docs`` turns on.
# * A gate nested inside another dependency, or added only by an ``include_router`` call. The check
#   reads a route's own top-level dependencies, so such a route is refused, which is the safe side.
#
# It does not check that a gate is correct, only that the route declared one. The mark is the
# declaration, and a factory that sets it takes on the duty to enforce.

#: The function attribute a gate dependency carries. Its value is ``True``.
_ROUTE_GATE_ATTR = "__route_gate__"
#: The function attribute an endpoint carries its :class:`RouteDeclaration` under.
_ROUTE_DECLARATION_ATTR = "__route_declaration__"

#: The ``detail`` of the refusal, so a caller and a test can tell it from a gate's own answer.
UNDECLARED_ROUTE_DETAIL = "this route declares no authorization"


@dataclass(frozen=True, slots=True)
class RouteDeclaration:
    """How an endpoint with no gate dependency is authorized, and why."""

    #: True for a route anonymous by design. False for a WebSocket endpoint that authorizes in its
    #: own body.
    public: bool
    #: Why. Never empty: a declaration with no reason is refused when it is made.
    reason: str


def mark_route_gate[G: Callable[..., Any]](gate: G) -> G:
    """Mark a gate dependency, so the route check and the route walk know it as one.

    Returns the SAME function object. Call it only from a factory whose dependency enforces
    authentication; the mark is what every route check trusts."""
    setattr(gate, _ROUTE_GATE_ATTR, True)
    return gate


def is_route_gate(call: object) -> bool:
    """True when ``call`` carries the gate mark :func:`mark_route_gate` sets."""
    return getattr(call, _ROUTE_GATE_ATTR, None) is True


def _declare[F: Callable[..., Any]](public: bool, reason: str) -> Callable[[F], F]:
    if not reason.strip():
        raise ValueError("a route declaration needs a reason")

    def mark(endpoint: F) -> F:
        setattr(endpoint, _ROUTE_DECLARATION_ATTR, RouteDeclaration(public, reason))
        return endpoint

    return mark


def public_route[F: Callable[..., Any]](reason: str) -> Callable[[F], F]:
    """Declare an endpoint anonymous by design. Apply it BELOW the route decorator."""
    return _declare(True, reason)


def authorizes_in_body[F: Callable[..., Any]](reason: str) -> Callable[[F], F]:
    """Declare a WebSocket endpoint that authorizes inside its own body. Refused on an HTTP route."""
    return _declare(False, reason)


def route_declaration_of(endpoint: object) -> RouteDeclaration | None:
    """The :class:`RouteDeclaration` an endpoint was marked with, or ``None``."""
    found = getattr(endpoint, _ROUTE_DECLARATION_ATTR, None)
    return found if isinstance(found, RouteDeclaration) else None


def _top_level_calls(route: object) -> list[object]:
    """The calls of ``route``'s top-level dependencies, the only ones the route check reads."""
    dependencies = getattr(getattr(route, "dependant", None), "dependencies", None) or ()
    return [dependency.call for dependency in dependencies]


def route_has_gate(route: object) -> bool:
    """True when one of ``route``'s top-level dependencies carries the gate mark."""
    return any(is_route_gate(call) for call in _top_level_calls(route))


def refusal_runs_on(route: object) -> bool:
    """True when :func:`refuse_undeclared_route` is among ``route``'s top-level dependencies, which
    is how ``create_app`` installs it on every route registered on the app."""
    return any(call is refuse_undeclared_route for call in _top_level_calls(route))


def route_is_declared(route: object, *, websocket: bool) -> bool:
    """True when ``route`` declares its authorization, as the module note above defines it."""
    if route_has_gate(route):
        return True
    declared = route_declaration_of(getattr(route, "endpoint", None))
    if declared is None:
        return False
    return declared.public or websocket


#: The route attribute that caches :func:`route_is_declared`. A route's dependencies and endpoint are
#: fixed once it is registered, so the answer is worked out on its first request only.
_DECLARED_CACHE_ATTR = "_mefor_route_declared"
#: The route attribute that holds a refused route's :class:`_RefusalTally`.
_REFUSALS_ATTR = "_mefor_route_refusals"

#: The shortest gap between two ERROR lines for one refused route (vault BACKLOG #2846). The first
#: refusal is always logged, and a burst costs one line a minute. Each line carries how many
#: refusals came since the previous one. Refusals after a burst's last line are held only in the
#: in-process tally (:func:`undeclared_route_refusals`). They reach the log only with the first
#: refusal of that route that comes at least this long after the last line; no timer flushes them,
#: and a restart loses them.
REFUSAL_LOG_INTERVAL_SECONDS = 60.0


@dataclass(slots=True)
class _RefusalTally:
    """How often one route was refused, and how many of those no log line has reported yet."""

    total: int = 0
    unlogged: int = 0
    logged_at: float | None = None


#: The tally for a refusal with no matched route in its scope. FastAPI always sets one, so this is
#: a fallback that keeps such a refusal counted and throttled rather than logged every time.
_UNKNOWN_ROUTE_REFUSALS = _RefusalTally()


def undeclared_route_refusals(route: object) -> int:
    """How many requests :func:`refuse_undeclared_route` has refused on ``route`` in this process."""
    tally = getattr(route, _REFUSALS_ATTR, None)
    return tally.total if isinstance(tally, _RefusalTally) else 0


def _record_refusal(route: object) -> None:
    """Count one refusal of ``route``, and log it at ERROR at most once per interval.

    The line names the route's path TEMPLATE and the counts, never the request: no query string,
    header or body reaches the log."""
    tally = getattr(route, _REFUSALS_ATTR, None) if route is not None else _UNKNOWN_ROUTE_REFUSALS
    if not isinstance(tally, _RefusalTally):
        tally = _RefusalTally()
        setattr(route, _REFUSALS_ATTR, tally)
    tally.total += 1
    tally.unlogged += 1
    now = time.monotonic()
    if tally.logged_at is not None and now - tally.logged_at < REFUSAL_LOG_INTERVAL_SECONDS:
        return
    log.error(
        "refused route %s: it has no gate dependency and no public declaration "
        "(%d refusals since the last log line, %d in all)",
        getattr(route, "path", "<unknown>"),
        tally.unlogged,
        tally.total,
    )
    tally.logged_at = now
    tally.unlogged = 0


async def refuse_undeclared_route(connection: HTTPConnection) -> None:
    """The app-level dependency: refuse a matched route that declares no authorization.

    An HTTP caller gets 403 with :data:`UNDECLARED_ROUTE_DETAIL`. A WebSocket is closed with policy
    violation (1008) before it is accepted. Either way the route is a defect in the code that
    registered it, so every refusal is counted, and an ERROR line is written at most once per
    :data:`REFUSAL_LOG_INTERVAL_SECONDS` for each route. That constant says what the log misses."""
    websocket = connection.scope.get("type") == "websocket"
    route = connection.scope.get("route")
    declared = getattr(route, _DECLARED_CACHE_ATTR, None)
    if declared is None:
        declared = route_is_declared(route, websocket=websocket)
        if route is not None:
            setattr(route, _DECLARED_CACHE_ATTR, declared)
    if declared:
        return
    _record_refusal(route)
    if websocket:
        raise WebSocketException(status.WS_1008_POLICY_VIOLATION)
    raise HTTPException(status.HTTP_403_FORBIDDEN, UNDECLARED_ROUTE_DETAIL)


def _gate(dependency: _Gate, authenticate: _Step) -> _Gate:
    """Mark a ``require*()`` closure as a gate, with the step that authenticates its caller.

    Returns the SAME function object. The route-gate walk recognises a gate by the mark
    :func:`mark_route_gate` sets and reads its permissions from the closure cells (see
    :func:`require`); neither attribute changes those.

    A factory whose gate refuses AHEAD of its base's sign-in check must put that refusal in its
    step too, in the same order, as :func:`require_phi_read` does with the hop refusal."""
    setattr(dependency, _BEFORE_BODY_ATTR, BeforeBody(authenticate, authenticates=True))
    return mark_route_gate(dependency)


def _authentication_of(gate: _Gate) -> _Step:
    """The authentication step of a gate built in this module, for a factory that wraps it."""
    found = before_body_of(gate)
    if found is None or not found.authenticates:
        raise TypeError(f"{gate!r} is not a gate built by a require*() factory")
    return found.step


def steps_before_body(dependant: Dependant) -> tuple[tuple[Callable[..., Any], _Step], ...]:
    """``(dependency, step)`` for each marked dependency of a route, in the order FastAPI runs them,
    up to and including its first gate. Empty when the route has no gate: a route with none parses
    its body for a caller with no session by design (sign-in itself is one).

    :class:`AuthenticatedBeforeBodyRoute` lists what this does not find."""
    steps: list[tuple[Callable[..., Any], _Step]] = []
    for dependency in dependant.dependencies:
        call = dependency.call
        found = before_body_of(call)
        if call is None or found is None:
            continue
        steps.append((call, found.step))
        if found.authenticates:
            return tuple(steps)
    return ()


class AuthenticatedBeforeBodyRoute(APIRoute):
    """Refuse a caller the gate would refuse for having no identity BEFORE the body is read.

    ``create_app`` sets this as the router's route class, so every route registered on the app
    itself is one, and a new gated route is covered with nothing to remember. Three kinds of
    route get FastAPI's own handler back unchanged: one that declares no body, where FastAPI
    already runs the gate before it reads anything; one with no gate; and one whose gate is not
    this module's (the web console's ``require_ui*``, whose routes declare no body).

    A body-taking route that declares no authorization is refused early too, with the answer
    :func:`refuse_undeclared_route` gives.

    WHAT IT DOES NOT COVER, at least. This list is the one place they are stated:

    * A route reached through ``include_router``. It is served by that router's route class,
      and FastAPI serves it from the include's own context. So a gate that the include call
      itself adds is not among the route's own dependencies, which is all this reads, and an
      override set on the app is not seen for it.
    * A gate nested inside another dependency. Only a route's top-level dependencies are read,
      which is also all ``scripts/security/route_gates.py`` reads.
    * A dependency that sits ahead of the gate and carries no mark. The gate's refusal answers
      before it, so a caller with no identity never reaches it. ``refuse_undeclared_route`` is one
      on every route, and it never refuses a route that has a gate.

    The refusal is not a copy of the gate's. The step raises the same ``HTTPException`` from the
    same function the gate calls, and it travels through the same exception handlers and the same
    middleware, so the response is the one the gate gives a request whose body had no problem.

    A dependency a test or an embedder overrides through ``dependency_overrides`` is skipped here.
    The override decides in its place, where FastAPI runs it."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()
        # ``body_field`` is the very condition FastAPI reads a body on before it solves
        # dependencies, so it is FastAPI's test and not a second opinion kept here.
        steps = steps_before_body(self.dependant) if self.body_field is not None else ()
        if (
            not steps
            and self.body_field is not None
            and refusal_runs_on(self)
            and not route_is_declared(self, websocket=False)
        ):
            # Vault BACKLOG #2604: a route that declares no authorization is refused before its
            # body is read too, so a malformed body cannot tell a caller that the route exists.
            steps = ((refuse_undeclared_route, refuse_undeclared_route),)
        if not steps:
            return handler
        provider = self.dependency_overrides_provider

        async def authenticate_then_read(request: Request) -> Response:
            overridden = getattr(provider, "dependency_overrides", None) or {}
            for call, step in steps:
                if call not in overridden:
                    await step(request)
            return await handler(request)

        return authenticate_then_read


async def _session_caller(
    request: Request, *, activity: bool = True
) -> tuple[AuthService | None, Identity]:
    """The authentication step of :func:`require`: the live service and the caller's identity.

    The service is ``None`` only on the ``allow_no_auth`` path, where the identity is the system
    one and none of the session checks apply. Raises the 503 or the 401 an unidentified caller
    gets. ``activity`` is :meth:`AuthService.identity_for_token`'s: False validates the session
    the same way and leaves its idle clock alone."""
    auth = get_auth(request)
    if auth is None:
        if _allow_no_auth(request.app.state):
            return None, _SYSTEM_IDENTITY
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "authentication is not configured")
    identity = await auth.identity_for_token(bearer_token(request), activity=activity)
    if identity is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    return auth, identity


async def _authenticate_session_before_body(request: Request) -> None:
    """The early-check step of every gate built on :func:`require`: refuse, or return nothing.

    It counts as no activity. The gate that runs after the body is what moves the session's idle
    clock, so a request whose body then fails to parse leaves the clock where it was, which is
    what such a request did before this check existed."""
    await _session_caller(request, activity=False)


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
        auth, identity = await _session_caller(request)
        if auth is None:
            return identity
        if identity.must_change_password and request.url.path not in _MUST_CHANGE_EXEMPT_PATHS:
            enrol_first = await auth.must_enrol_before_rotating(identity)
            if not (enrol_first and (request.method, request.url.path) in _ENROL_FIRST_ROUTES):
                # BACKLOG #1141 (ASVS 6.4.5): this refusal is the renewal instruction every
                # non-browser caller receives, so it states when the credential dies. The detail
                # stays a string that STARTS with the old text, because clients match on it as a
                # substring (``ide/src/engineStatusModel.ts`` ``classifyForbidden``).
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    _password_change_required(
                        await pending_credential_deadline_for(auth, identity.user_id),
                        suffix=_ENROL_FIRST_SUFFIX if enrol_first else "",
                    ),
                )
        # ASVS 6.3.3 — MFA is an ACCESS gate, not only a step-up gate. Ordering is load-bearing in
        # BOTH directions. must_change stays FIRST: a fresh account (a new user) is
        # must_change AND mfa_pending with NO factor, so leading with MFA would point it at
        # /auth/mfa-verify with nothing to prove there — the brick. Under require_mfa it ENROLS
        # first, through _ENROL_FIRST_ROUTES above, and only then rotates (ADR 0197 Amendment A);
        # with the requirement off it rotates first, and /me/password lets it, because the factor
        # refusal below skips an account with no factor.
        # A must-change account that HAS a factor (an admin reset) is sent the other way: /me/password
        # refuses it with X-MFA-Required, and /auth/mfa-verify is must-change-exempt so it can answer
        # (BACKLOG #1954). And this stays ABOVE the permission loop: refusing below it would tell an
        # unverified caller whether it holds the permission, a free authorization oracle.
        route = (request.method, request.url.path)
        if mfa_gate and route not in _MFA_EXEMPT_ROUTES:
            pending = not await auth.mfa_satisfied(bearer_token(request))
        elif mfa_gate and route == _PASSWORD_CHANGE_ROUTE:
            pending = await auth.password_change_owes_factor(bearer_token(request))
        else:
            pending = False
        if pending:
            await auth.audit_mfa_denied(identity, request.url.path, client=client_ip(request))
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "multi-factor verification required; POST /auth/mfa-verify then retry",
                headers={"X-MFA-Required": "1"},
            )
        # BACKLOG #1139 (ASVS 6.3.7): an account with no notification address sets one first. BELOW
        # the factor gate, so a password-only session is sent to prove its factor before it can
        # choose where notices go. ABOVE the permission loop, for the oracle reason given there.
        if identity.must_set_notify_email and mfa_gate and route not in _NOTIFY_EMAIL_EXEMPT_ROUTES:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                NOTIFY_EMAIL_REQUIRED_DETAIL,
                headers={"X-Notify-Email-Required": "1"},
            )
        for permission in permissions:
            if not identity.has(permission):
                await auth.audit_permission_denied(
                    identity, permission, request.url.path, client=client_ip(request)
                )
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, f"missing permission: {permission.value}"
                )
        # BACKLOG #195a (ASVS 16.3.2): record the authorization GRANT. Under [diagnostics].audit_all_authz
        # — ON by default since BACKLOG #1277, threaded onto app.state — EVERY satisfied route is audited,
        # GETs included, except the PHI-view grants that the PHI-access audit path already records. With
        # the switch off, the method guard drops every GET (including the polled GET /approvals, which
        # carries APPROVALS_APPROVE) and the permission set drops every read/monitoring grant, leaving
        # only the sensitive/state-changing surface on a NON-GET request.
        audit_all = _audit_all_authz(request.app.state)
        if audit_all or request.method != "GET":
            audited = _grant_audit_permission(permissions, audit_all=audit_all)
            if audited is not None:
                await auth.audit_permission_granted(
                    identity, audited, request.url.path, client=client_ip(request)
                )
        return identity

    return _gate(dependency, _authenticate_session_before_body)


#: The step-up refusal's detail for a session whose step-up is a password or directory re-proof.
#: Clients and tests read it, so it stays byte-for-byte what it was before BACKLOG #2158.
_STEP_UP_DETAIL = "step-up re-verification required; POST /me/reauth then retry"
#: The same refusal for an ``oidc`` session. ``POST /me/reauth`` refuses such a session (BACKLOG
#: #296), so naming it would send the client to a second 403. This names the leg built for that
#: session, the web console's IdP step-up, much as ``POST /me/reauth``'s own refusal does. It
#: promises no JSON retry: that leg runs in a browser and re-keys the session it steps up, so a
#: bearer client cannot finish it (docs/SECURITY.md says which gates such a client can never
#: pass). It does not name ``POST /auth/mfa-verify``, although a TOTP code there does stamp the
#: window for an account that holds one: whether it should is BACKLOG #2142's open question.
_IDP_STEP_UP_DETAIL = (
    "step-up re-verification required; this session steps up at the identity provider, in a"
    " browser, through the web console at /ui/reauth, not with a password"
)
#: Set to ``idp`` on an ``oidc`` session's step-up refusal, so a client can branch on a header
#: rather than parse the detail. Absent on every other refusal.
_STEP_UP_VIA_HEADER = "X-Step-Up-Via"


async def _step_up_refusal(
    auth: AuthService, token: str | None, action: str | None = None
) -> HTTPException:
    """The 403 every JSON step-up gate raises, for the session that holds ``token``.

    One place for the step-up raise sites (BACKLOG #2158), at least the four ``require_step_up*``
    and ``require_reauth_only*`` factories and :func:`refuse_from_new_address`. It reads the
    session only on the refusal path, so a request that passes pays nothing for it. ``action`` adds
    ``X-Step-Up-Action`` for the per-action gates (ADR 0077)."""
    headers = {"X-Step-Up-Required": "1"}
    if action is not None:
        headers["X-Step-Up-Action"] = action
    if await auth.session_steps_up_at_idp(token):
        headers[_STEP_UP_VIA_HEADER] = "idp"
        return HTTPException(status.HTTP_403_FORBIDDEN, _IDP_STEP_UP_DETAIL, headers=headers)
    return HTTPException(status.HTTP_403_FORBIDDEN, _STEP_UP_DETAIL, headers=headers)


async def refuse_from_new_address(request: Request) -> None:
    """Refuse a request whose session was last verified from another host (vault BACKLOG #2620).

    The step-up gates already asked this. The PHI reads and the paced writes did not, so on a
    first deployment a bearer token replayed from a second address would have read message bodies
    and started or stopped connections with no signal. Callers: :func:`require_phi_read`,
    :func:`require_paced` and the HTTP reveal path in ``api/app.py`` (``_admit_reveal``). It gives
    them the step-up gates' refusal: 403 + ``X-Step-Up-Required: 1``, cleared by a
    ``POST /me/reauth`` from the new address, which re-anchors the session. An ``oidc`` session is
    sent to the IdP step-up instead (:func:`_step_up_refusal`). A first sighting writes
    ``auth.admin_action_new_ip`` and a notice, deduped and capped per session as
    :meth:`AuthService.flag_new_client_ip` says.

    It is NOT in :func:`require`, deliberately: the base gate carries the monitoring polls, and an
    operator whose address changes behind a NAT pool would be refused on every one until a step-up.

    Costs one session read per request while ``[auth].admin_new_ip_step_up`` is on, and one more
    on a refusal, to pick its wording. The gate has
    already read the session through :func:`require`, but the identity it returns does not carry
    the anchor address. A no-op with no auth service."""
    auth = get_auth(request)
    if auth is None:
        return
    token = bearer_token(request)
    if await auth.flag_new_client_ip(token, client_ip(request), path=request.url.path):
        raise await _step_up_refusal(auth, token)


def require_paced(*permissions: Permission) -> Callable[[Request], Awaitable[Identity]]:
    """Like :func:`require`, plus per-actor anti-automation PACING on the state-changing admin
    surface (BACKLOG #193, ASVS 2.4.2) — but WITHOUT the MFA / step-up window. For the mutating admin
    routes that warrant paced throttling yet not a full step-up re-proof, for example connection
    start/stop/restart and statistics reset. docs/SECURITY.md lists the set. A
    non-GET request from an actor over the per-actor rate is refused early with 429 + Retry-After: 1
    (logged, not silent) before the identity is returned. Reuses the SAME #193 limiter as
    :func:`require_step_up` via :func:`_enforce_admin_write_pacing`, so pacing coverage is uniform
    across both gates. The embedding/no-auth path is unaffected (no per-actor identity to key on).

    A request from a host the session has not verified from is refused with the step-up answer
    (:func:`refuse_from_new_address`, vault BACKLOG #2620). That runs BEFORE the pacing charge, so
    a refusal here spends none of the holder's write budget (the BACKLOG #1973 rule the console's
    gate states). The step-up gates still pace before they ask, so a refusal there does."""
    base = require(*permissions)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None:
            await refuse_from_new_address(request)
            _enforce_admin_write_pacing(request, auth, identity)
        return identity

    return _gate(dependency, _authentication_of(base))


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
    # The same read the shim makes, verified issuer included (BACKLOG #2237).
    return peercert_from_ssl_object(ssl_object)


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
        alert_sink_for(state).cert_expiry(
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
    :class:`AuthService`, extracts the peer cert (:func:`peer_cert_from_request`), maps its issuer and
    subject/SAN to an account id (:func:`client_cert_principal_under_issuer`), and resolves that id
    to an Identity. Returns ``None`` — DENY-BY-DEFAULT — when cert-identity is unconfigured, auth is
    disabled, no cert is presented, the issuer is not listed, the subject is unmapped/spoofed under its
    issuer, or the mapped account is unknown/disabled, or is a directory account the directory does
    not confirm on this request (BACKLOG #2316, :meth:`AuthService.identity_for_cert_user_id`)."""
    cert_map: Mapping[str, Mapping[str, str]] = (
        getattr(request.app.state, "tls_client_cert_identities", {}) or {}
    )
    if not cert_map:
        return None  # feature off (empty map) — byte-identical to no cert-identity
    auth = get_auth(request)
    if auth is None:
        return None
    peer_cert = peer_cert_from_request(request)
    # Only the names listed under the cert's OWN issuer are consulted (BACKLOG #2237): the same
    # subject issued by another CA in [api].tls_client_ca_file maps to nothing.
    user_id = client_cert_principal_under_issuer(peer_cert, cert_map)
    if user_id is None:
        return None  # unmapped / spoofed subject → deny-by-default
    # BACKLOG #2238: the map targets the users-row id, which a rename cannot move to another account.
    identity = await auth.identity_for_cert_user_id(user_id)
    # ASVS 6.4.5: the cert is verified, allow-listed AND resolved to a live account here, so its expiry
    # is worth reporting. The label is the account's username, as it was before the map held ids: an
    # id in an alert says nothing to the operator reading it. Resolved first so the label never names
    # an id the store does not hold. Advisory only: it never gates the resolution.
    if identity is not None and peer_cert is not None:
        note_client_cert_expiry(request, peer_cert, f"api-client:{identity.username}")
    return identity


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

    # The step below lives INSIDE this factory on purpose. tests/test_docs_security_pathways.py
    # pins that the primitive admitting a certificate identity is referenced from here alone, so
    # a second route cannot widen the plane unseen. A module-level helper would move that
    # reference out from under the pin.
    async def caller(request: Request) -> Identity:
        identity = await resolve_client_cert_identity(request)
        if identity is None:
            # No subject in the message (no cert / unmapped) — never echo the presented subject
            # (could be attacker-chosen); a generic 401 keeps the deny-by-default surface uniform.
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "client certificate not authorized")
        return identity

    async def dependency(request: Request) -> Identity:
        identity = await caller(request)
        # An identity implies a live AuthService — :func:`resolve_client_cert_identity` returns None
        # when auth is absent or disabled. Narrowed rather than asserted so a later refactor of that
        # resolver degrades to a missing audit row instead of a 500 on the request path.
        auth = get_auth(request)
        for permission in permissions:
            if not identity.has(permission):
                log.warning(
                    "service-cert authz denied: actor=%s path=%s missing=%s",
                    identity.username,
                    request.url.path,
                    permission.value,
                )
                if auth is not None:
                    # ASVS 16.3.2 / BACKLOG #1197 — the cert plane's failed authorization attempts have
                    # to reach the tamper-evident chain, not only the application log. Measured at HEAD
                    # before this call existed: a refused cert-identity wrote ZERO audit rows while
                    # :func:`require`'s denial wrote ``auth.permission_denied`` for the same principal on
                    # the same store in the same run.
                    #
                    # The GRANT side is deliberately NOT mirrored here, and that is a scope decision
                    # rather than an oversight: a grant row is per-request, and #1197's part (a)
                    # measured that the audit chain has no drain — ``[retention].audit_days`` is
                    # reserved and unenforced, ``[retention].max_db_mb`` ships at 0 — so widening the
                    # per-request trail waits on that drain. A denial is rare by construction and does
                    # not. Note the admission is not silent today either: the one shipped route on this
                    # gate, ``GET /service/identity``, writes its own ``service_cert_auth`` row in the
                    # ROUTE BODY. That covers authentication for that route only; a future route built
                    # on this factory inherits nothing, which is the gap the grant work would close.
                    #
                    # ``client`` (ADR 0150) is threaded HERE and not inherited: this factory is the
                    # one authorization gate that does NOT delegate to :func:`require` — it
                    # authenticates through :func:`resolve_client_cert_identity` and runs its own
                    # permission loop — so "fix require() and the factories follow" is true of
                    # ``require_paced`` / ``require_step_up`` and false of this one. A cert plane's
                    # peer address is the whole of what identifies the calling SERVICE host, since
                    # there is no session row to join back to.
                    await auth.audit_permission_denied(
                        identity, permission, request.url.path, client=client_ip(request)
                    )
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, f"missing permission: {permission.value}"
                )
        return identity

    return _gate(dependency, caller)


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
    identity work, so a production-PHI instance serving over an insecure hop refuses to emit PHI.

    And it refuses a read from a host the session has not verified from, with the step-up answer
    (:func:`refuse_from_new_address`, vault BACKLOG #2620), before the budget is charged: a read
    that will not be served must not spend the holder's quota."""
    base = require(*permissions)
    authenticate = _authentication_of(base)

    async def before_body(request: Request) -> None:
        # The hop refusal answers ahead of sign-in in the dependency below, so it does here too.
        enforce_phi_read_hop(request)
        await authenticate(request)

    async def dependency(request: Request) -> Identity:
        enforce_phi_read_hop(request)
        identity = await base(request)
        await refuse_from_new_address(request)
        enforce_phi_read_pacing(request, identity)
        return identity

    return _gate(dependency, before_body)


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
    have re-proved its credential -- at a local login that owes no factor, via ``POST /me/reauth``,
    or with a code at ``POST /auth/mfa-verify`` (``verify_mfa`` stamps the window), or at their
    console twins -- within ``[auth].step_up_max_age_seconds``. A directory login opens no window
    (BACKLOG #1144). Gates the highly sensitive admin / replay / config flows; a stale session is
    refused with 403 (the console then prompts to re-authenticate and retries). An ``oidc``
    session's refusal names the IdP leg instead of ``POST /me/reauth`` (:func:`_step_up_refusal`).
    The embedding/no-auth path is unaffected (there is no session to step up)."""
    base = require(*permissions)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None:
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
                raise await _step_up_refusal(auth, token)
        return identity

    return _gate(dependency, _authentication_of(base))


def require_reauth_only(*permissions: Permission) -> Callable[[Request], Awaitable[Identity]]:
    """Like :func:`require_step_up` but with **only** the password step-up — **not** the MFA gate.

    Used by the MFA *enrollment* endpoints: a user enrolling their first second factor (or a
    ``require_mfa`` administrator who has not enrolled yet) cannot satisfy an MFA gate, so a
    :func:`require_step_up` there would deadlock. Re-proving the password still defends a stolen
    session from silently enrolling an attacker-controlled authenticator (WP-14). An ``oidc``
    session re-proves at the IdP instead, and its refusal says so (:func:`_step_up_refusal`).

    ``mfa_gate=False`` extends that same deadlock carve-out to the ASVS 6.3.3 ACCESS gate now applied
    by :func:`require`: without it the enrollment routes would sit behind a factor the caller does
    not yet have."""
    base = require(*permissions, mfa_gate=False)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None:
            token = bearer_token(request)
            # Same new-client-IP contextual-risk layer as require_step_up (WP-L3-13); the MFA gate is
            # intentionally skipped here (enrollment would otherwise deadlock — see the docstring).
            new_ip = await auth.flag_new_client_ip(token, client_ip(request), path=request.url.path)
            if new_ip or not await auth.has_recent_step_up(token):
                raise await _step_up_refusal(auth, token)
        return identity

    return _gate(dependency, _authentication_of(base))


async def _action_step_up_ok(auth: AuthService, token: str | None, action: str) -> bool:
    """The step-up decision for a per-action route (ADR 0077): when action-binding is enforced
    (default), a fresh **single-use grant BOUND to** ``action`` (consumed here); when the org opted
    out (``[auth].require_action_step_up = false``), the legacy session-window recency. Split out so
    ``require_step_up_action`` and ``require_reauth_only_action`` share one place for the fallback.

    The factor-binding refusal below sits ABOVE that fork, so no knob reaches it (ASVS 6.3.3; the
    bypass it closes is the ADR 0077 amendment of 2026-09-14)."""
    # Above the fork rather than inside each branch, for two reasons. A control a config knob can
    # switch off is not a control, and the opt-out branch is where the hole was. And `new_ip` aside,
    # this is the one check that must precede `has_action_step_up`, which POPS the grant: refusing
    # after it would burn the proof the caller just minted and re-prompt them into the same wall.
    if await auth.factor_binding_is_blocked(token, action):
        return False
    if auth.action_step_up_required:
        return await auth.has_action_step_up(token, action)
    return await auth.has_recent_step_up(token)


def require_step_up_action(
    action: str, *permissions: Permission, proof_in_route: bool = False
) -> Callable[[Request], Awaitable[Identity]]:
    """Like :func:`require_step_up`, but the step-up must be a fresh proof **bound to** ``action``
    (single-use), not the shared session window (ADR 0077; ASVS 7.5.1 / 8.2.4). Keeps the MFA gate —
    used for the durable-takeover op that still requires the current second factor (**disable-MFA**): a
    hijacked session inside the login window can neither satisfy MFA it lacks nor reuse a broad window.

    On a stale/missing grant it 403s with ``X-Step-Up-Required`` **and** ``X-Step-Up-Action: <action>``,
    so the console echoes the action back as ``POST /me/reauth {"purpose": …}``. An ``oidc`` session
    is told the IdP leg instead (:func:`_step_up_refusal`). When the org opts out it falls back to
    the legacy session-window behaviour.

    ``proof_in_route=True`` moves ONLY the proof into the route, which must then call
    :func:`spend_step_up_action` before it runs anything or files anything. Everything else still
    runs here: permissions, pacing, the MFA gate, the new-address check and the factor-binding
    refusal. Purge and reload use it (vault BACKLOG #2625 with #2445), so a repeat that only rejoins
    the requester's open dual-control hold needs no new proof and burns none."""
    base = require(*permissions)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None:
            token = bearer_token(request)
            # BACKLOG #1148 (ASVS 2.4.2): charge the SAME per-actor anti-automation bucket
            # require_step_up charges, in the SAME position — first, so a throttled write is refused
            # before any further work. Without this, promoting a route from require_step_up to this
            # factory SILENTLY STRIPS the pacing floor while reading as a hardening change, because
            # the action binding is visible in the diff and the lost pacing is not. That already
            # happened once: PATCH /users/{user_id} was promoted and lost it, and
            # docs/SECURITY.md filed it under "No limiter of any kind" until then. Adding it here
            # closes that too rather than only sparing the routes #1148 promotes.
            _enforce_admin_write_pacing(request, auth, identity)
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
            if proof_in_route:
                # Every check but the pop. The factor-binding refusal is the one _action_step_up_ok
                # runs above its fork; it pops nothing, so it can run here as well as at the spend.
                if new_ip or await auth.factor_binding_is_blocked(token, action):
                    raise await _step_up_refusal(auth, token, action)
            elif new_ip or not await _action_step_up_ok(auth, token, action):
                raise await _step_up_refusal(auth, token, action)
        return identity

    return _gate(dependency, _authentication_of(base))


async def spend_step_up_action(request: Request, action: str) -> None:
    """The proof half of ``require_step_up_action(action, ..., proof_in_route=True)``.

    Spends the caller's single-use grant for ``action``, or reads the session window when the org
    opted out, and refuses as the dependency would: 403 with ``X-Step-Up-Action``. A route calls it
    once it knows the request will file a hold or run, and never on a path that does neither. With
    no auth service attached it does nothing, as the dependency does."""
    auth = get_auth(request)
    if auth is None:
        return
    token = bearer_token(request)
    if not await _action_step_up_ok(auth, token, action):
        raise await _step_up_refusal(auth, token, action)


def require_reauth_only_action(
    action: str, *permissions: Permission
) -> Callable[[Request], Awaitable[Identity]]:
    """Like :func:`require_reauth_only` (password step-up, **no** MFA gate) but the proof must be bound
    to ``action`` (single-use) — the action-scoped analogue for the **factor-enrollment** routes (TOTP
    enroll/confirm) a required-but-unenrolled session must still be able to reach
    (an MFA gate there would deadlock — WP-14). Re-proving the password still defends a hijacked session
    from binding an attacker authenticator, and now that proof is tied to *this* action, not the login
    window (ADR 0077). Same ``X-Step-Up-Action`` header + org opt-out as :func:`require_step_up_action`,
    and the same IdP wording for an ``oidc`` session (:func:`_step_up_refusal`).

    Carries the same ``mfa_gate=False`` opt-out as :func:`require_reauth_only`, for the same reason;
    the session-terminate routes use it too. A pending session on an account that HAS a factor is
    still refused (see ``AuthService._PENDING_REFUSED_ACTIONS``), with ``X-MFA-Required`` and not
    a step-up header: a password re-proof mints it nothing, so pointing it at ``POST /me/reauth``
    would loop a client that already typed the right password (BACKLOG #1951)."""
    base = require(*permissions, mfa_gate=False)

    async def dependency(request: Request) -> Identity:
        identity = await base(request)
        auth = get_auth(request)
        if auth is not None:
            token = bearer_token(request)
            new_ip = await auth.flag_new_client_ip(token, client_ip(request), path=request.url.path)
            # After the new-IP signal, so a refused request still records it, and before the grant
            # check, which pops: a refusal here must not burn a grant. Audited like require()'s MFA
            # gate, since this is the same refusal reached past that gate's carve-out.
            if await auth.factor_binding_is_blocked(token, action):
                await auth.audit_mfa_denied(identity, request.url.path, client=client_ip(request))
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "multi-factor verification required; POST /auth/mfa-verify then retry",
                    headers={"X-MFA-Required": "1"},
                )
            if new_ip or not await _action_step_up_ok(auth, token, action):
                raise await _step_up_refusal(auth, token, action)
        return identity

    return _gate(dependency, _authentication_of(base))


async def optional_identity(request: Request) -> Identity | None:
    """Best-effort caller identity that **never raises** — for read-only, non-PHI endpoints (e.g.
    ``GET /ai/policy``) that must answer even to a tokenless client, while still reporting the
    caller's RBAC when a valid token is present.

    Returns the full-access system identity when no service is attached and ``allow_no_auth`` is
    set (embedding/dev); ``None`` when auth is unconfigured/fail-closed or the token is missing/invalid. The
    ``must_change_password`` gate is intentionally *not* applied — this surfaces non-sensitive policy,
    not PHI. The ASVS 6.3.3 **MFA access gate is excluded for the same reason, deliberately**: this
    resolver answers tokenless callers by contract, so a second-factor gate here could only ever
    downgrade an already-public answer, never protect anything. Both consumers (``GET /health``,
    ``GET /ai/policy``) are non-PHI."""
    auth = get_auth(request)
    if auth is None:
        return _SYSTEM_IDENTITY if _allow_no_auth(request.app.state) else None
    return await auth.identity_for_token(bearer_token(request))


def ws_token(websocket: WebSocket) -> str | None:
    """Extract a WebSocket bearer token from the Authorization header.

    Header-only: the legacy ``?token=`` query-string fallback was removed because a session token in
    a URL leaks into proxy/access logs and the Referer header (ASVS Session Management; API-3). The
    web console does not authenticate here: a browser cannot set the header on a WebSocket
    handshake, so its same-origin handshake uses the session cookie through the console's own hook
    (``authorize_ui_ws``). When that hook declines, the route still calls this, finds no header and
    gets ``None``."""
    header = websocket.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[len("Bearer ") :].strip() or None
    return None


def _ws_origin_allowed(websocket: WebSocket) -> bool:
    """Whether the WebSocket handshake's ``Origin`` is acceptable (ASVS 4.4.2).

    A native (non-browser) client sends **no** ``Origin`` header — that is allowed. A browser always
    sends one; it is allowed only if listed in ``[api].ws_allowed_origins`` (default empty → every
    browser Origin is rejected). This blocks cross-site WebSocket hijacking at the handshake, before
    ``accept()``.

    No native client ships today. The shipped client is the browser web console. When the console
    is mounted, its same-origin handshake is tried first by the console's cookie hook
    (``authorize_ui_ws``), which checks the Origin itself and does not read ``ws_allowed_origins``.
    A handshake the hook declines, or any handshake while the console is not mounted, comes here."""
    origin = websocket.headers.get("origin")
    if not origin:
        return True  # native client (no browser Origin)
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
    if auth is None:
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
        await auth.audit_mfa_denied(identity, websocket.url.path, client=client_ip(websocket))
        return None
    # BACKLOG #1139: an account that owes a notification address does not stream either. BELOW the
    # factor check, as in require(), so a password-only probe still leaves its auth.mfa_denied row.
    if identity.must_set_notify_email:
        return None
    for permission in permissions:
        if not identity.has(permission):
            # Audit the denial like the HTTP require() path does, so a revoked/under-privileged
            # user probing the stats feed leaves a trail too (review low-9). ``client`` via the shared
            # :func:`client_ip` (see its docstring for why a WS-only extractor was refused).
            await auth.audit_permission_denied(
                identity, permission, websocket.url.path, client=client_ip(websocket)
            )
            return None
    # BACKLOG #195a (ASVS 16.3.2): audit the grant. Under [diagnostics].audit_all_authz — ON by default
    # since BACKLOG #1277 — every satisfied WS route is audited (PHI-view still excluded). THIS RUNS ONCE
    # PER CONNECTION, NOT PER MESSAGE, so the shipped stats feed writes one row per connect however long
    # it streams; that is why the flipped default costs nothing measurable here. With the switch off only
    # the sensitive set is audited, and /ws/stats requires MONITORING_READ, which is not in it.
    audit_all = _audit_all_authz(websocket.app.state)
    audited = _grant_audit_permission(permissions, audit_all=audit_all)
    if audited is not None:
        await auth.audit_permission_granted(
            identity, audited, websocket.url.path, client=client_ip(websocket)
        )
    return identity
