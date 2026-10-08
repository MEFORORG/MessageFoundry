# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Core /ui pages: login/logout, dashboard, messages + parse-tree, dead-letters, replay, and the step-up re-auth flow (GET/POST /ui/reauth + the WebAuthn leg) — the sole consumer of the write-action registry (ADR 0065)."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Annotated, Any, TypedDict
from urllib.parse import parse_qsl, urlencode, urlsplit
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import TypeAdapter, ValidationError

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.models import (
    DeadLetterReplayRequest,
    EditResendRequest,
    MessageBody,
    PendingApprovalResponse,
    ResendRequest,
)
from messagefoundry.api.security import (
    get_auth,
    pending_credential_deadline_for,
    public_route,
)
from messagefoundry.api.validation import (
    EPOCH_SECONDS_MAX,
    ConnectionName,
    EpochSeconds,
    IdempotencyKey,
)
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.service import (
    STEP_UP_ACTION_MESSAGE_EDIT_RESEND,
    STEP_UP_ACTION_MESSAGE_RESEND,
    AuthService,
    Elevation,
    MfaStatus,
)
from messagefoundry.auth.tokens import hash_bytes, hash_token
from messagefoundry.connection_names import is_connection_name
from messagefoundry.parsing import HL7PeekError, parse_tree
from messagefoundry.parsing.tree import ParseTreeTooLargeError

from .. import pages
from .._auth import (
    CLEAR_SITE_DATA_HEADER,
    CLEAR_SITE_DATA_VALUE,
    WEBAUTHN_EXTRA_MISSING_NOTICE,
    WEBAUTHN_RP_CHANGED_NOTICE,
    WEBAUTHN_RP_MISSING_NOTICE,
    RepeatRefused,
    allow_reauth_attempt,
    assert_not_cross_site,
    assert_same_origin,
    clear_session_cookie,
    confined_before_its_factor,
    consume_continuation,
    continues_after_reauth,
    is_unlock_action,
    login_redirect_response,
    lookup_ui_action,
    must_change_target,
    proof_spent_for,
    proxied_loopback_host,
    reauth_landing,
    register_ui_action,
    rekey_continuations,
    require_ui,
    require_ui_step_up,
    require_ui_step_up_action,
    rotation_comes_first,
    session_token,
    set_session_cookie,
    settle_ui_action_step_up,
    spend_ui_action_step_up,
    webauthn_rp,
)
from .._html import CSP_PROBE_SRC
from .._service import _service
from ..pages._common import _seg
from ._common import UI_BODY_FILTER_RULES, blank_to_none, check_filters, for_echo
from .oidc import reauth_idp_response

_log = logging.getLogger(__name__)

#: Login-page outcome codes that mean "a session just ended" and therefore carry Clear-Site-Data.
#: The header itself (and every server-driven expiry redirect that carries it) lives in
#: :mod:`.._auth` — see :data:`.._auth.CLEAR_SITE_DATA_VALUE`. ``pwchanged`` belongs here for the same
#: reason as ``loggedout``: a password change revokes EVERY session for the user. It is belt — the
#: 303 that sends the browser here already carries the header via ``clear_session_cookie`` — but a
#: browser can reach this landing by another route (Back, a bookmark) with the cookie already gone,
#: which is exactly the case ``_has_stale_session_cookie`` below cannot detect.
_CLEAR_SITE_DATA_LOGIN_CODES = frozenset({"expired", "loggedout", "pwchanged"})

#: How many report bodies of one CSP violation BATCH the WARNING line summarises before it is
#: truncated to a count. The reports are attacker-influenceable, so the log line is bounded.
_CSP_REPORT_SUMMARY_MAX = 5

#: What the MFA gate and the re-auth form say when ``verify_mfa``, ``reauth`` or
#: ``finish_webauthn_assertion`` refused a directory account the directory did not confirm (BACKLOG
#: #2023, #2027, #2239). The code, password or passkey was never checked, so "invalid code",
#: "incorrect password" or "passkey verification failed" would be false.
_DIRECTORY_UNCONFIRMED_ERROR = (
    "The directory could not confirm your account. Try again later, or ask an administrator."
)


def _directory_unconfirmed(elevation: Elevation) -> bool:
    """``Elevation.directory_unconfirmed``, read so an engine that predates the field degrades.

    The console ships as a separately versioned wheel. When this was written the seam digest
    recorded ``verify_mfa``'s signature but not ``Elevation``'s fields, so an older engine would
    pass the handshake and then raise ``AttributeError`` here. The digest records those fields since
    BACKLOG #2015, so such an engine now ships a different seam; the fallback stays as a second
    guard. The ``allow_reauth_attempt`` precedent in ``_auth.py`` is the same.
    """
    return bool(getattr(elevation, "directory_unconfirmed", False))


#: The message log's received-date bounds, validated by the SAME annotated type the JSON ``/messages``
#: route declares — so the two surfaces refuse the same instants (BACKLOG #1744).
_EPOCH_BOUND: TypeAdapter[float] = TypeAdapter(EpochSeconds)

#: What the console says when a received-date bound is not a value the JSON route would accept. The
#: window is DERIVED from that route's own constant rather than transcribed, so it cannot go stale.
#: Fixed text otherwise: pydantic's message quotes the offending input, which is never reflected.
_BAD_BOUND_MESSAGE = (
    "the received-date bounds must be UTC datetime-local values between "
    f"{datetime.fromtimestamp(0.0, UTC):%Y-%m-%dT%H:%M} and "
    f"{datetime.fromtimestamp(EPOCH_SECONDS_MAX, UTC):%Y-%m-%dT%H:%M}"
)

#: What each /ui message route reveals, declared once per route (BACKLOG #2346, ASVS 14.2.6).
#:
#: ASVS 14.2.6 asks that complete data stay masked "unless the user specifically views it", and
#: BACKLOG #1187 reads that strictly: opening a message is not the act of viewing its summary or its
#: body. So a route reveals the summary or fetches the body ONLY when this table says it does, and
#: the answer is a property of the route the operator chose, never of the permissions they hold.
#: Holding ``messages:view_raw`` makes a reveal possible; the request to a revealing route is the act.
#:
#: - The bare detail page reveals nothing. The dead-letter "view" link, the redirect after a replay
#:   or an edit-resend, and a typed URL all land there, and none of them is an act aimed at the data.
#: - ``/summary`` is where the message list and content search link from the MASKED summary, so the
#:   click is aimed at the summary. The detail page also offers it as a "Reveal" link.
#: - ``/body`` is the detail page's "Show raw message" link. The summary is derived from the body, so
#:   showing the body and masking the summary beside it would hide nothing.
#: - The parse tree, the editor and the editor's reject arm exist to show the body.
#: - ``/errors`` reveals the error-tier text: the message's error, each delivery's last error and
#:   each event's detail (BACKLOG #2436, owner ruling R12). The detail page offers it as a "Reveal"
#:   link beside each masked value, and the dead-letter list links each masked last error to it.
#:   It is its own act, so no other row in this table declares it: the scrubber that cleans that
#:   text is not de-identification, and a body reveal is aimed at the body, not at the errors.
#:
#: A route that is not listed reveals nothing, and :func:`_message_body` refuses to fetch a body for
#: a route that does not declare ``body``. That refusal covers the helpers only: a handler calling
#: ``core.get_message`` or ``core.get_message_body`` directly would go around it, which is what the
#: console suite's source test over these modules fails on. Attachment downloads are not in this
#: table; they are their own audited route.
UI_MESSAGE_REVEALS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "/ui/messages/{message_id}": frozenset(),
        "/ui/messages/{message_id}/summary": frozenset({"summary"}),
        "/ui/messages/{message_id}/body": frozenset({"summary", "body"}),
        "/ui/messages/{message_id}/errors": frozenset({"errors"}),
        "/ui/messages/{message_id}/parse-tree": frozenset({"body"}),
        "/ui/messages/{message_id}/edit": frozenset({"body"}),
        "/ui/messages/{message_id}/edit-resend": frozenset({"body"}),
    }
)


def _declared_reveals(request: Request) -> frozenset[str]:
    """This request's route's row in :data:`UI_MESSAGE_REVEALS`; nothing for an unlisted route."""
    path = getattr(request.scope.get("route"), "path", None)
    return UI_MESSAGE_REVEALS.get(path or "", frozenset())


class _MsgFilters(TypedDict):
    """The message-log filter values echoed back into the form, keyed as ``pages.messages`` names
    them so the three render arms can splat one dict instead of repeating six keywords each."""

    channel_id: str
    status: str
    message_type: str
    control_id: str
    received_from: str
    received_to: str


# Edit-and-resubmit (ADR 0090 §9, BACKLOG #153). The GET editor page is the step-up `unlock`
# continuation (a GET form the re-auth flow can 303-GET-redirect back to); the body-carrying POST
# `/edit-resend` is deliberately NOT a registered continuation — its `reauth_next` maps a stale-window
# step-up to this /edit page, so the operator re-submits inside a fresh window (mirrors /ui/users).
# The re-auth mints the edit-resend grant (vault BACKLOG #2625). The editor only checks that it is
# held, and the POST spends it, so the operator proves who they are BEFORE typing an edit.
register_ui_action(
    r"^/ui/messages/[^/?#]+/edit$",
    Permission.MESSAGES_EDIT,
    auto_retry=False,
    unlock=True,
    action=STEP_UP_ACTION_MESSAGE_EDIT_RESEND,
    label="Open the message edit page",
)


def _edit_page(request: Request) -> str:
    """The editor an edit-resend POST re-opens after a re-auth, never the POST path itself (a
    re-POST would drop the edited body). The gate and the spend both send the browser here."""
    return request.url.path.removesuffix("/edit-resend") + "/edit"


# The PHI pages `require_ui(..., phi=True)` gates, as unlock continuations (vault BACKLOG #2620).
# That gate sends a read from a host the session has not verified from to /ui/reauth, carrying the
# page's own target, and /ui/reauth acts only on a registered continuation: without these the
# operator would land on /ui with the session still anchored elsewhere.
# QUERY-TOLERANT, for the reason `_auth.is_unlock_action` sets out: a filtered or deferred list must
# come back filtered or deferred, not as a broader read than the operator asked for. Each route's
# own Query bounds still judge the query. Every path here serves GET only. The message pattern
# excludes `search`, which routes/search.py registers with its own flags, so the first-match lookup
# never depends on import order. The reveal routes are registered in monitoring.py.
register_ui_action(
    r"^/ui/messages(\?[^#]*)?$",
    Permission.MESSAGES_READ,
    auto_retry=False,
    unlock=True,
    label="View the message list",
)
register_ui_action(
    r"^/ui/messages/(?!search(?:$|[/?#]))[^/?#]+(/(summary|body|errors|parse-tree))?(\?[^#]*)?$",
    Permission.MESSAGES_VIEW_RAW,
    auto_retry=False,
    unlock=True,
    label="View a message",
)
register_ui_action(
    r"^/ui/messages/[^/?#]+/attachments/[^/?#]+(\?[^#]*)?$",
    Permission.MESSAGES_VIEW_RAW,
    auto_retry=False,
    unlock=True,
    label="View a message attachment",
)
register_ui_action(
    r"^/ui/dead-letters(\?[^#]*)?$",
    Permission.MESSAGES_READ,
    auto_retry=False,
    unlock=True,
    label="View the dead letters",
)
register_ui_action(
    r"^/ui/connection/[^/?#]+/events/[^/?#]+/reason(\?[^#]*)?$",
    Permission.MESSAGES_VIEW_SUMMARY,
    auto_retry=False,
    unlock=True,
    label="View the reason for a connection event",
)

# Resend to an ALTERNATE outbound (ADR 0090 §§1-8, BACKLOG #123/#1500). The GET confirm page is the
# step-up `unlock` continuation; the POST behind it is deliberately NOT registered — its
# `reauth_next` maps a stale-window step-up back to that confirm page, which re-renders with a fresh
# idempotency key.
#
# QUERY-TOLERANT, for the reason `_auth.is_unlock_action` sets out: the whole selection rides the
# query, `_reauth_redirect` puts the entire continuation into `next`, and `lookup_ui_action` /
# `is_unlock_action` fullmatch the RAW value — so a path-only pattern would match nothing and
# dead-end the flow at /ui with the selection silently gone.
# KEEP THE OPTIONAL GROUP rather than pinning `\?to=...`: this form also fullmatches the bare route
# TEMPLATE, which is what keeps the coverage guard in test_webui.py able to see this entry.
# The re-auth mints the resend grant (vault BACKLOG #2625), which the POST behind the page spends.
register_ui_action(
    r"^/ui/messages/[^/?#]+/resend-confirm(\?[^#]*)?$",
    Permission.MESSAGES_RESEND,
    auto_retry=False,
    unlock=True,
    action=STEP_UP_ACTION_MESSAGE_RESEND,
    label="Open the message resend confirmation",
)

#: Fixed text for each refused resend, rendered IN PLACE on the confirm page.
#:
#: THE OUTCOME IS NOT A REDIRECT TO THE MESSAGE DETAIL PAGE, and that is the whole reason these are
#: notices rather than ``?e=`` codes. The detail page is ``require_ui(MESSAGES_VIEW_RAW)``, so a role
#: holding ``messages:resend`` without ``messages:view_raw`` — the exact role this lane's permission
#: choice exists to serve — followed such a redirect into a raw JSON 403 and learned nothing about
#: whether a delivery had been queued. MEASURED on a mounted app before this was changed. Answering
#: on the page the operator is already standing on needs no permission they do not have.
#:
#: Caller-supplied text still travels nowhere: these are module constants, and ``exc.detail`` (which
#: quotes the operator's own ``to``/``source``, and for a key conflict a PRIOR resend's message id
#: and target) is neither rendered nor logged.
RESEND_MALFORMED_NOTICE = (
    "That resend did not run — nothing was queued. That is not a usable connection name. Check the "
    "spelling and try again."
)
RESEND_MISSING_NOTICE = (
    "That resend did not run — nothing was queued. The message or the target outbound connection "
    "was not found. Check them and try again."
)
RESEND_DENIED_NOTICE = (
    "That resend did not run — nothing was queued. You are not authorized to resend to that "
    "outbound connection."
)
#: The 409 arm covers SEVERAL separately-worded engine refusals — a target that is stopped, not
#: deployed or owned by another engine shard (ADR 0090 §7), a source that is absent, retention-nulled
#: or ambiguous (§4/§5), and an idempotency key already used for a different message or target (§4).
#: They arrive as one status code, and ``exc.detail`` is the only thing that separates them.
#:
#: SO THE NOTICE SAYS "AT LEAST", NOT A CLOSED LIST (CLAUDE.md §11, SDS-3.6). An enumeration here
#: would be a completeness claim about a set this module cannot observe: it already missed
#: ``ResendKeyConflict`` once, and an operator who checks every named cause and finds nothing wrong
#: is worse off than one told the list is partial.
RESEND_BLOCKED_NOTICE = (
    "That resend did not run — nothing was queued. The engine refused it. Common causes: the target "
    "outbound is stopped, not deployed, or owned by another engine shard; or this message has no "
    "single stored delivery body to copy. Check those first."
)

#: Which notice each refused status becomes. Anything outside this map is not a refusal this route
#: knows how to explain, so it is re-raised rather than reported as one of these.
_RESEND_NOTICES: dict[int, str] = {
    403: RESEND_DENIED_NOTICE,
    404: RESEND_MISSING_NOTICE,
    409: RESEND_BLOCKED_NOTICE,
}

#: Ceiling on ``to`` and ``source`` in the query, BELOW the 256 the connection-name rule allows.
#:
#: ``_reauth_redirect`` packs the whole continuation into ``GET /ui/reauth``'s ``next``, which is
#: ``Query(max_length=512)``, and ``quote()`` expands each ``=`` and ``&`` to three characters. At the
#: model's own 256 ceiling a stale-window resend therefore built a 542-character ``next`` and the
#: re-auth page answered a raw 422 — MEASURED, at 231 characters each. 200 keeps the worst case at
#: 478. A connection name longer than this cannot be resent from the console; it still can over the
#: JSON API, which has no continuation to carry.
_RESEND_NAME_MAX = 200


_IDEMPOTENCY_KEY: TypeAdapter[str] = TypeAdapter(IdempotencyKey)


def _spent_name(request: Request, key: str, to: str | None, rest: str) -> str:
    """What a spent proof is recorded under: the key, what it acts on (the message, and the
    outbound or, for a re-ingress, none) and ``rest``, the remainder of the request (the resend's
    source, a digest of the edited body). Only an identical request, a double-click, is a repeat;
    the same key aimed elsewhere, or carrying anything else, needs a proof of its own."""
    return "\x00".join((request.path_params["message_id"], to or "", key, rest))


def _body_digest(request: Request, raw: str) -> str:
    """Names an edited body in a spend record without holding the body (PHI) in memory. Hashed
    once per request and kept in the ASGI scope, since a body may run to megabytes and the hash
    runs on the event loop; the gate and the route both ask for it."""
    cache = request.scope.setdefault("mf_2625", {})
    digest = cache.get("digest")
    if not isinstance(digest, str):
        digest = hash_bytes(raw.encode("utf-8", "surrogatepass"))
        cache["digest"] = digest
    return digest


def _fits_key(value: str) -> bool:
    """Whether ``value`` passes the idempotency-key rule. Checked before it reaches a store query."""
    try:
        _IDEMPOTENCY_KEY.validate_python(value)
    except ValidationError:
        return False
    return bool(value)


def _resend_confirm_next(request: Request) -> str:
    """Where a resend POST refused for its proof sends the browser: the confirm page, carrying
    the selection. ``_seg`` on the id for the reason the page builder applies it: a ``?`` or ``#``
    here produces a ``next`` the write-action registry cannot fullmatch, and an unmatched
    continuation is dropped SILENTLY. Measured."""
    path = f"/ui/messages/{_seg(request.path_params['message_id'])}/resend-confirm?"
    return path + urlencode({k: request.query_params.get(k, "") for k in ("to", "source")})


def _csp_report_bodies(doc: object) -> list[dict[str, object]] | None:
    """Normalize either wired delivery shape to the LIST of report bodies it carries, or ``None`` when
    the payload is not an object at all: the legacy ``report-uri`` body
    (``{"csp-report": {"document-uri": ..., "violated-directive": ..., "blocked-uri": ...}}``, always
    exactly one) and the modern Reporting-API ``report-to`` batch (a top-level ARRAY whose entries
    carry a ``body`` dict keyed ``documentURL``/``effectiveDirective``/``blockedURL``,
    ``application/reports+json``). Never raises on hostile input — the report is
    attacker-influenceable DATA, never instructions.

    Returning every entry rather than the first is LOAD-BEARING (ASVS 3.7.5). The Reporting API
    batches per endpoint, and the enforcement canary provokes one report per page load on every
    conforming browser, so a genuine violation raised on the same page load arrives in the SAME POST,
    behind the canary. A first-entry-only view classified that batch by the canary and dropped the real
    violation to DEBUG — the exact detection hole the external-canary design exists to avoid.
    """
    if isinstance(doc, list):
        bodies: list[dict[str, object]] = []
        for entry in doc:
            if isinstance(entry, dict):
                body = entry.get("body", entry)
                if isinstance(body, dict):
                    bodies.append(body)
        return bodies
    if isinstance(doc, dict):
        inner = doc.get("csp-report", doc)
        return [inner] if isinstance(inner, dict) else []
    return None


def _csp_report_summary(report: dict[str, object]) -> str:
    """A bounded, PHI-free one-line summary of ONE CSP violation report body (either delivery shape).
    Returns ``"empty"`` when nothing usable is present."""
    # Accept both the hyphenated report-uri keys and the camelCase report-to keys, labelling the
    # summary by the stable report-uri name in either case.
    field_specs = (
        ("document-uri", "documentURL"),
        ("violated-directive", "effectiveDirective"),
        ("blocked-uri", "blockedURL"),
    )
    fields: list[str] = []
    for legacy_key, modern_key in field_specs:
        value = report.get(legacy_key)
        if value is None:
            value = report.get(modern_key)
        if value:
            fields.append(f"{legacy_key}={str(value)[:256]}")
    return "; ".join(fields) or "empty"


def _request_origin(request: Request) -> str | None:
    """This deployment's own ORIGIN (``scheme://host[:port]``, lowercased) for a same-origin
    comparison, or ``None`` when it cannot be established.

    Follows the precedence of ``_auth._origin_matches`` — ``[api].public_origin`` is authoritative
    when configured, else the request's own ``Host`` header, except ``None`` behind a proxy in front
    of a loopback bind (``proxied_loopback_host``, BACKLOG #2217) — but, unlike that function's
    Host-only fallback, it also carries the SCHEME. A violation report's blocked URL is absolute, so
    the scheme IS observable here, and ``http://<our-host>/ui/static/csp-probe.js`` on an https
    deployment is NOT our canary. Behind a TLS-terminating proxy that neither sets ``public_origin``
    nor rewrites ``scope['scheme']`` the comparison simply fails and the canary's own reports WARN instead of being filtered — noisier,
    never quieter, which is the only safe direction for a filter on a security log.
    """
    public_origin: str | None = getattr(request.app.state, "public_origin", None)
    if public_origin:
        parts = urlsplit(public_origin)
        if not parts.scheme or not parts.netloc:
            return None
        return f"{parts.scheme.lower()}://{parts.netloc.lower()}"
    if proxied_loopback_host(request.app.state):
        return None  # a proxy's forwarded Host is not ours to vouch for (BACKLOG #2217)
    host = request.headers.get("host")
    return f"{request.url.scheme.lower()}://{host.lower()}" if host else None


def _is_expected_csp_probe_report(report: dict[str, object], origin: str | None) -> bool:
    """Whether THIS report body is the one violation the 3.7.5 enforcement canary is designed to
    provoke — a conforming browser refusing OUR OWN un-nonced ``/ui/static/csp-probe.js``.

    The match is SAME-ORIGIN — scheme AND ``host[:port]`` — plus same-path, and nothing else. The path
    alone is not sufficient: it is attacker-selectable on an attacker-hosted payload, so a host-blind
    match would let ``https://evil.example/ui/static/csp-probe.js`` — an injected script load a real
    CSP blocked — be filed as the expected canary and dropped to DEBUG. ``origin`` is this
    deployment's own ``scheme://host[:port]`` (:func:`_request_origin`); a relative ``blocked-uri``
    (some browsers report a bare path) is same-origin by construction, and an absolute URL must match
    it case-insensitively. Unknown origin fails CLOSED — the report warns.

    Being an external script rather than an inline one is what makes any filtering safe at all: a
    blocked INLINE canary reports ``blocked-uri: "inline"`` with the same directive and document as a
    blocked injected inline script, so any filter wide enough to drop the canary would also drop the
    report a real XSS attempt produces. Directive naming is deliberately NOT part of the match
    (browsers report ``script-src-elem`` or ``script-src`` depending on version), and neither is the
    document URI (every /ui page emits the canary, so it discriminates nothing).
    """
    blocked = report.get("blocked-uri")
    if blocked is None:
        blocked = report.get("blockedURL")
    if not isinstance(blocked, str):
        return False
    parts = urlsplit(blocked)
    # Compare paths: browsers report the absolute URL, but tolerate a bare path too. Query/fragment are
    # stripped so a cache-buster can never smuggle a non-probe URL past the match.
    if parts.path != CSP_PROBE_SRC:
        return False
    if not parts.netloc:
        return True
    return origin is not None and f"{parts.scheme.lower()}://{parts.netloc.lower()}" == origin


def _parse_tree_response(message_id: str, raw: str) -> HTMLResponse:
    """The parse-tree page for ``raw``. Blocking, so the route runs it off the event loop; the
    response is built here too, so encoding a large page does not run on the loop either.

    Non-HL7 bodies (X12/DICOM/binary) have no HL7 tree and say so rather than 500; a tree past
    the node cap says it is too large and points at the raw view (vault BACKLOG #2762)."""
    try:
        nodes = parse_tree(raw)
    except ParseTreeTooLargeError as exc:
        return HTMLResponse(pages.parse_tree_too_large(message_id, str(exc)))
    except HL7PeekError as exc:
        return HTMLResponse(pages.parse_tree_unavailable(message_id, str(exc)))
    return HTMLResponse(pages.parse_tree_page(message_id, nodes))


async def _has_stale_session_cookie(request: Request, auth: AuthService | None) -> bool:
    """Whether this request presents a session cookie that no longer authenticates (ASVS 14.3.1).

    A first-time visitor carries no cookie and gets an ordinary login form; a browser arriving with a
    dead ``mf_session`` is landing AFTER a termination — idle/absolute expiry, revoke, admin disable —
    and its cached PHI pages must be dropped even when the redirect that sent it here was not ours
    (a bookmark, a Back navigation, or a client that never ran the watchdog). Validated with
    ``activity=False``: probing a dead session must not be treated as user activity.
    """
    token = session_token(request)
    if not token:
        return False
    if auth is None:
        return True  # a cookie with no auth configured can never authenticate
    return await auth.identity_for_token(token, activity=False) is None


def register(app: FastAPI, deps: UiDeps) -> None:
    """Register the phase-0 /ui routes (login, dashboard, messages, dead-letters, replay,
    reauth). Runs first in ``_UI_REGISTRARS``; a page lane adds its own
    ``_register_<area>(app)`` + one tuple entry below, so parallel lanes never edit this
    shared block (ADR 0065 §multi-session-build)."""
    core = deps.core

    @app.get("/ui/session-status")
    async def ui_session_status(
        request: Request,
        service: AuthService = Depends(_service),
        # activity=False (ASVS 14.3.1) is LOAD-BEARING: this probe is the client watchdog's heartbeat,
        # so refreshing the idle clock from it would make the watchdog keep the very session alive it
        # exists to notice the end of. No permission is required beyond a live session — every
        # authenticated page needs it, including a must-change-confined one.
        # allow_mfa_pending is MANDATORY, not a convenience: the confinement page at /ui/mfa carries
        # the same watchdog, so gating this probe would 303 it to /ui/mfa on every heartbeat and the
        # page would fight its own poll.
        identity: Identity = Depends(
            require_ui(allow_must_change=True, allow_mfa_pending=True, activity=False)
        ),
    ) -> JSONResponse:
        """The session watchdog's heartbeat (ASVS 14.3.1).

        Reaching this AT ALL is the liveness signal — ``require_ui`` 303s to the login page the moment
        the session is idle-expired, absolute-expired or revoked, and the client treats that redirect
        as termination. The body carries the ABSOLUTE deadline as **remaining seconds**, never a
        wall-clock the client would have to trust against its own (possibly wrong, possibly
        adversary-set) system time, and it is read from the session RECORD rather than computed from
        ``[auth].session_absolute_hours`` — a federated session's deadline may be capped lower by the
        IdP's ``id_token.exp``, so settings arithmetic would over-state it.

        ``expires_secs`` is null when the record cannot be resolved; the client then relies on the
        server verdict and its stale-contact bound alone rather than inventing a deadline.
        """
        remaining: int | None = None
        token = session_token(request)
        if token:
            # The SAME indexed point-lookup ``identity_for_token`` just did (``require_ui`` above),
            # not a per-user session listing: this probe runs every 30s in every open console tab, and
            # ``list_sessions`` is an unindexed scan on all three backends.
            record = await service.store.get_session(hash_token(token))
            if record is not None:
                remaining = max(0, int(record.expires_at - datetime.now(UTC).timestamp()))
        return JSONResponse({"expires_secs": remaining})

    @app.get("/ui/login", response_class=HTMLResponse)
    @public_route("the sign-in form")
    async def ui_login_form(
        request: Request, e: str | None = Query(None, max_length=32)
    ) -> HTMLResponse:
        auth = get_auth(request)
        # NO ad_enabled COMPUTATION. The simple-bind login pathway is retired (BACKLOG #1137), so
        # there is no AD password form to gate and nothing here to decide.
        #
        # What stood here was a getattr fallback from the layer-1 split, reading
        # ad_password_login_enabled and degrading to ad_enabled for an older engine. Once layer 2
        # DELETED that setting the fallback stopped being a compatibility shim and became the
        # defect: it fell through to ad_enabled -- the directory BIND, still true because SSO and
        # OIDC need it -- and re-rendered the AD password form the retirement had just removed.
        # A shim that survives the thing it was shimming inverts into a feature switch.
        sso_enabled = auth is not None and auth.kerberos_available
        # getattr: an older engine (seam < 10) has no oidc_available property at all, and a bare
        # attribute read would AttributeError rather than degrade (the exposure_protected
        # precedent). oidc_available, not oidc_enabled -- the LINK should disappear while the IdP
        # is known-down, even though the start leg still attempts per-request (AC-8).
        oidc_enabled = bool(getattr(auth, "oidc_available", False))
        resp = HTMLResponse(pages.login(e, sso_enabled=sso_enabled, oidc_enabled=oidc_enabled))
        # ASVS 14.3.1: this render IS the post-termination landing page when either the outcome code
        # says so (the watchdog's ?e=expired, the redirect target of POST /ui/logout, or the
        # server's own expiry redirect) OR the browser still presents a session cookie that no
        # longer authenticates — a stale cookie IS a terminated session, whatever URL it landed on.
        # Tell the browser to drop that session's cached representations so Back / bfcache cannot
        # resurrect a PHI page whose session no longer exists.
        if e in _CLEAR_SITE_DATA_LOGIN_CODES or await _has_stale_session_cookie(request, auth):
            resp.headers[CLEAR_SITE_DATA_HEADER] = CLEAR_SITE_DATA_VALUE
        return resp

    @app.post("/ui/login")
    @public_route("sign-in itself; a session does not exist yet")
    async def ui_login(request: Request) -> Response:
        # ASVS 3.5.1 — FIRST statement, ahead of the per-address login budget below: a cross-site
        # credential POST is refused having spent no rate-limit token and run no password verify. The
        # unauthenticated leg is exactly where SameSite=Strict supplies nothing (there is no session
        # cookie yet), so this origin check is the only login-CSRF control available here.
        assert_same_origin(request)
        auth = get_auth(request)
        if auth is None:
            raise HTTPException(503, "authentication is not configured")
        client = request.client.host if request.client else None
        if not auth.allow_login_attempt(client):
            raise HTTPException(429, "too many login attempts", headers={"Retry-After": "30"})
        # Parse the urlencoded login form with stdlib — the engine has no python-multipart dep, so
        # Form()/request.form() would fail; a same-origin login POST is always urlencoded here.
        form = dict(parse_qsl((await request.body()).decode("utf-8", "replace")))
        # L5b (ADR 0068 §8): the form rides the SAME auth.login seam as the JSON surface, with
        # allow-listed provider values only; absent stays LOCAL (regression-pinned). The browser
        # AD-password sign-in is RETIRED (BACKLOG #1137): the login page renders no provider
        # selector, and "ad" stays in the allow-list only so the ENGINE (_dispatch_login) is the
        # single point that refuses and audits it. Directory accounts sign in by Windows SSO or
        # OIDC, and the AD bind as the user survives only as the step-up re-bind at /ui/reauth
        # (and the JSON /me/reauth).
        provider_value = form.get("provider", "local")
        if provider_value not in ("local", "ad"):
            return RedirectResponse("/ui/login?e=bad", status_code=303)
        outcome = await auth.login(
            form.get("username", ""),
            form.get("password", ""),
            provider=AuthProvider.AD if provider_value == "ad" else AuthProvider.LOCAL,
            client=client,
            # ADR 0197 (BACKLOG #1131): the authenticator-code field, shown on every sign-in. A blank
            # one is today's two-step flow. Clamped as the JSON route bounds it; a longer value is
            # simply a wrong code.
            totp_code=form.get("totp_code", "")[:16] or None,
            # ASVS 7.2.4: the Set-Cookie below REPLACES whatever session cookie this browser sent,
            # so the engine ends that one session as part of a SUCCESSFUL mint, rather than leave
            # it valid and unreachable until it expires. A failed sign-in ends nothing.
            supersedes=session_token(request),
        )
        if not outcome.ok or outcome.token is None:
            return RedirectResponse("/ui/login?e=bad", status_code=303)
        # A must-change account goes straight to the browser rotation page (L4b) — every other
        # /ui route would bounce it there anyway (require_ui). An MFA-pending session lands on the
        # second-factor page for the same reason (ASVS 6.3.3). must_change comes first for an
        # account with NO factor (a new user holding an admin-issued password): it is BOTH. With
        # require_mfa off it can only rotate; under it, it enrols TOTP first (ADR 0197 Amendment A).
        # An account that HAS a factor (an admin reset keeps them) proves it first, because the
        # rotation page refuses it until then (BACKLOG #1954), and the factor page sends it on to
        # the rotation page afterwards.
        #
        # UX only — require_ui and the rotation page are what actually enforce, and they cover the
        # other two cookie-minting legs (Kerberos SSO, the OIDC callback) without this branch.
        if outcome.must_change_password:
            # The password page, the factor page, or -- under require_mfa with no TOTP -- the
            # enrolment page first (ADR 0197 Amendment A): the one decision must_change_target makes.
            target = await must_change_target(auth, outcome.token)
        elif outcome.mfa_required:
            target = "/ui/mfa"
        else:
            target = "/ui"
        resp = RedirectResponse(target, status_code=303)
        set_session_cookie(resp, outcome.token, request=request)
        return resp

    @app.post("/ui/logout")
    @public_route("sign-out must work for a session every gate would refuse")
    async def ui_logout(request: Request) -> Response:
        # ASVS 3.5.1 — FIRST statement, before the session is revoked below. This route deliberately
        # carries NO Depends gate (so a must-change-confined session can still sign itself out — the
        # affordance ASVS 7.4.4 makes visible), which means the origin check is the only
        # request-provenance control it will ever have: without it a cross-site POST the browser
        # attaches the cookie to would forcibly terminate the operator's session.
        #
        # IT ALSO CHARGES NO WRITE BUDGET, AND THAT IS DELIBERATE (BACKLOG #287). Having no Depends
        # gate, it never reaches `require_ui`, where every other non-GET /ui route now spends
        # `allow_admin_write`. Do not "correct" that: a throttled logout is a signed-in operator who
        # cannot sign out, which is the 7.4.4 affordance failing exactly when someone is trying to
        # end a session they no longer trust. Signing out is also not the operation a write budget
        # exists to bound — it REMOVES authority rather than exercising it. Written down because an
        # unwritten right answer is indistinguishable from an oversight, and this one now sits
        # conspicuously alone.
        assert_same_origin(request)
        auth = get_auth(request)
        token = session_token(request)
        if auth is not None and token:
            await auth.logout(token)
        resp = RedirectResponse("/ui/login?e=loggedout", status_code=303)
        # ASVS 14.3.1: revoking server-side and deleting the cookie leaves the browser's CACHED
        # representations of the operator's PHI pages behind, which Back / bfcache can resurrect.
        # ``clear_session_cookie`` emits Clear-Site-Data itself — cookie deletion IS the termination,
        # so the two cannot be written apart (see its docstring for the scope rationale).
        clear_session_cookie(resp, request)
        return resp

    @app.get("/ui", response_class=HTMLResponse)
    async def ui_dashboard(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
    ) -> HTMLResponse:
        rows = await core.list_connections(request=request, engine=engine, identity=identity)
        # BACKLOG #1152: the landing page is where a fresh operator forms the impression that RBAC
        # is broken, so it is where the unprovisioned state gets a sentence. Read off the identity,
        # never off `not rows` — an estate with no connections configured yet is a different empty.
        return HTMLResponse(pages.dashboard(rows, unprovisioned=identity.has_no_channels))

    @app.get("/ui/connections", response_class=HTMLResponse)
    async def ui_connections(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        # activity=False (ASVS 14.3.1): the dashboard's 5s live-table refresh is timer-driven, not
        # user activity — it must not keep an abandoned tab's session alive.
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ, activity=False)),
    ) -> HTMLResponse:
        rows = await core.list_connections(request=request, engine=engine, identity=identity)
        return HTMLResponse(pages.connections_fragment(rows))

    @app.get("/ui/connection/{name}", response_class=HTMLResponse)
    async def ui_connection_details(
        name: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MONITORING_READ)),
    ) -> HTMLResponse:
        return await _connection_details_page(name, request, engine, identity, reveal=None)

    # The per-event reveal on this page (BACKLOG #2443, ASVS 14.2.6, owner ruling R12): the
    # "Reveal" link beside a masked event reason. The request is the act, so it returns that one
    # event's reason whole, the engine audits it as ``connection_event_reveal``, and the next bare
    # load is masked again. messages:view_summary unlocks the reason, and phi=True charges the
    # PHI-read budget the in-process handler call does not charge for itself.
    @app.get("/ui/connection/{name}/events/{event_id}/reason", response_class=HTMLResponse)
    async def ui_connection_event_reason(
        name: str,
        event_id: int,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(
            require_ui(Permission.MONITORING_READ, Permission.MESSAGES_VIEW_SUMMARY, phi=True)
        ),
    ) -> HTMLResponse:
        return await _connection_details_page(name, request, engine, identity, reveal=event_id)

    async def _connection_details_page(
        name: str, request: Request, engine: Any, identity: Identity, *, reveal: int | None
    ) -> HTMLResponse:
        # Compose the detail view from existing monitoring handlers (no new PHI surface): find the row in
        # the (already channel-scoped) connection list, then its recent events. A singular /ui/connection/
        # path avoids colliding with the /ui/connections/{purge-confirm,...} action routes.
        rows = await core.list_connections(request=request, engine=engine, identity=identity)
        row = next((r for r in rows if r.name == name), None)
        if row is None:
            raise HTTPException(404, "connection not found")
        # Events are recorded + RBAC-scoped by the RAW connection name (channel_id for a source,
        # destination for an outbound), NOT the composite display name — pass the raw name so the events
        # actually match and a channel-scoped operator isn't spuriously denied (+ audited) on their own.
        events_key = (
            row.destination if (row.role == "destination" and row.destination) else row.channel_id
        )
        try:
            # Pass EVERY param explicitly: called directly (not over HTTP), any FastAPI Query(...) default
            # left unfilled arrives as a Query object (kind would reach the store un-iterable → 500).
            events = await core.list_connection_events(
                engine=engine,
                identity=identity,
                connection=events_key,
                kind=None,
                since=None,
                limit=50,
                request=request,
                reveal=reveal,
            )
        except HTTPException:
            events = []  # still show the connection's info + stats if events are RBAC-scoped out
        return HTMLResponse(pages.connection_details(row, events, revealed=reveal))

    @app.get("/ui/messages", response_class=HTMLResponse)
    async def ui_messages(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_READ, phi=True)),
        # The four metadata filters keep a plain `str` declaration and are checked in the body
        # against _common.UI_BODY_FILTER_RULES (BACKLOG #1740). Annotating them would make FastAPI
        # answer 422 and discard the form, and this form already refuses its two date bounds with
        # a 400 re-render that gives the operator back what they typed (BACKLOG #1744). One form
        # refusing its own six fields two different ways is the shape being avoided here.
        channel_id: str | None = Query(None, max_length=256),
        status_filter: str | None = Query(None, alias="status", max_length=64),
        message_type: str | None = Query(None, max_length=64),
        control_id: str | None = Query(None, max_length=256),
        received_from: str | None = Query(None, max_length=32),  # datetime-local (UTC)
        received_to: str | None = Query(None, max_length=32),
        defer: bool = Query(False),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> HTMLResponse:
        # Arriving pre-filled from a connection name (defer=1) with no explicit dates → default a 1-day
        # window (UTC). The operator adjusts and clicks Search (a plain submit, no defer) to run it.
        if defer and not received_from and not received_to:
            now = datetime.now(UTC)
            received_from = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M")
            received_to = now.strftime("%Y-%m-%dT%H:%M")

        def _epoch(value: str | None) -> float | None:
            """One ``datetime-local`` bound as the epoch seconds the JSON handler takes.

            BACKLOG #1744: this used to DROP a malformed bound and search without it, so the operator
            read a result set under a filter they had typed and the engine had not applied. It now
            RAISES and the route refuses, which is what the JSON twin does (422). One rule, three
            rejects — accept only what that twin would accept."""
            if not value:
                return None
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is not None:
                # An offset the old replace(tzinfo=UTC) silently re-stamped as a DIFFERENT instant. A
                # datetime-local field never sends one, so only a hand-built URL reaches this.
                raise ValueError("a received-date bound carries its own offset")
            return _EPOCH_BOUND.validate_python(parsed.replace(tzinfo=UTC).timestamp())

        # What ARRIVED, for the rules to judge. Separate from the echo dict below, and the split
        # is load-bearing: for_echo strips the control characters, so checking the echo would hand
        # the rules a value the operator did not send and a NUL in message_type would PASS.
        arrived: dict[str, object] = {
            "channel_id": channel_id,
            "status": status_filter,
            "message_type": message_type,
            "control_id": control_id,
        }
        # Echoed back into the filter form by every arm below, so the operator never loses what they
        # typed — built once, as routes/search.py does with its own criteria. A TypedDict rather than
        # a plain dict so mypy still matches each key to its named parameter through the ``**``.
        typed = _MsgFilters(
            channel_id=for_echo(channel_id),
            status=for_echo(status_filter),
            message_type=for_echo(message_type),
            control_id=for_echo(control_id),
            received_from=for_echo(received_from),
            received_to=for_echo(received_to),
        )
        # BACKLOG #1740: the four metadata filters, against the SAME rules GET /messages declares.
        # A direct handler call runs no request validation, so without this the console searched on
        # a value the JSON route refuses.
        refusal = check_filters(UI_BODY_FILTER_RULES["/ui/messages"], arrived)
        if refusal is None:
            try:
                epoch_from, epoch_to = _epoch(received_from), _epoch(received_to)
            except ValueError:  # fromisoformat, or pydantic on an out-of-window instant
                refusal = _BAD_BOUND_MESSAGE
        if refusal is not None:
            return HTMLResponse(pages.messages(None, error=refusal, **typed), status_code=400)

        if defer:
            # Form-only landing: pre-filled, NOT run until the operator submits (#4b).
            return HTMLResponse(pages.messages(None, deferred=True, **typed))

        # A BLANK BOX IS NOT A FILTER, and without the calls below it would be. A browser GET form
        # submits every field it has, so leaving a box empty sends ``status=``, which arrives here
        # as "" rather than None; the store's filter builder gates on ``is not None`` and emits
        # ``status = ''``, which no row matches. MEASURED 2026-09-18 on three messages:
        # ``?channel_id=ch1`` renders all three and ``?channel_id=ch1&status=`` renders none — so
        # pressing Search on this page's own form with any box left empty returned an empty log.
        # ``blank_to_none`` is the whole fix, and it belongs here rather than in the store: an empty
        # string is a legitimate value to a query API, and it is the BROWSER FORM that means "unset"
        # by it. The two date bounds already went through ``_epoch``, which returns None for a
        # blank, which is why they were never affected.
        data = await core.list_messages(
            request,
            engine=engine,
            identity=identity,
            # ``blank_to_none`` is the fix the paragraph above measured.
            channel_id=blank_to_none(channel_id),
            status=blank_to_none(status_filter),
            message_type=blank_to_none(message_type),
            control_id=blank_to_none(control_id),
            received_from=epoch_from,
            received_to=epoch_to,
            limit=limit,
            offset=offset,
        )
        return HTMLResponse(pages.messages(data, **typed))

    async def _open_message(
        message_id: str, request: Request, engine: Any, identity: Identity
    ) -> Any:
        """Open one message through the engine's audited ``get_message``, revealing the summary only
        when this route declares ``summary`` in :data:`UI_MESSAGE_REVEALS` (BACKLOG #2346), and the
        error-tier text only when it declares ``errors`` (BACKLOG #2436)."""
        reveals = _declared_reveals(request)
        return await core.get_message(
            message_id,
            request,
            engine=engine,
            identity=identity,
            reveal_summary="summary" in reveals,
            reveal_errors="errors" in reveals,
        )

    async def _message_body(
        message_id: str, request: Request, engine: Any, identity: Identity
    ) -> str:
        """The raw body through the engine's own audited fetch (BACKLOG #2345). The engine records
        the audit row's surface as ``console`` itself, because this call arrives on a /ui route; the
        console passes no surface. Every caller's /ui gate must assert messages:view_raw with
        phi=True, because calling the handler in-process skips its own require_phi_read gate (see
        CoreHandlers).

        Refuses unless this route declares ``body`` in :data:`UI_MESSAGE_REVEALS` (BACKLOG #2346).
        That is a programming error, not an operator one, so it fails loudly rather than rendering."""
        if "body" not in _declared_reveals(request):
            raise RuntimeError(
                "a /ui route fetched a message body without declaring 'body' in UI_MESSAGE_REVEALS"
            )
        # Annotated so the console's use of MessageBody.raw joins the discovered seam surface: a
        # reshaped MessageBody then moves the digest and fails the handshake, not a page render.
        body: MessageBody = await core.get_message_body(
            message_id, request, engine=engine, identity=identity
        )
        return body.raw

    async def _detail_page(
        message_id: str, request: Request, engine: Any, identity: Identity
    ) -> HTMLResponse:
        """The detail page, showing what this route declares and nothing more (BACKLOG #2346)."""
        reveals = _declared_reveals(request)
        detail = await _open_message(message_id, request, engine, identity)
        raw = (
            await _message_body(message_id, request, engine, identity)
            if "body" in reveals
            else None
        )
        return HTMLResponse(
            pages.message_detail(
                detail,
                raw,
                summary_revealed="summary" in reveals,
                errors_revealed="errors" in reveals,
            )
        )

    # Four routes, one page. What each reveals is its row in UI_MESSAGE_REVEALS, so the act is the
    # route the operator chose: the bare path reveals nothing, /summary is the click on a masked
    # summary, /body is the "Show raw message" click, and /errors is the click on masked error text
    # (BACKLOG #2436). All four carry the gate the detail page always had, because each still opens
    # the message through the view_raw-gated get_message.
    #
    # Separate handlers rather than one function under stacked decorators, on purpose. The
    # PHI-read scope count in docs/SECURITY.md is derived from require_ui(..., phi=True) CALL SITES
    # (tests/test_security_doc_rate_limits.py), so one shared gate would state fewer charging
    # views than there are routes that charge. Each gate is also pinned per route by the /ui route
    # map in SECURITY.md.
    @app.get("/ui/messages/{message_id}", response_class=HTMLResponse)
    async def ui_message_detail(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_VIEW_RAW, phi=True)),
    ) -> HTMLResponse:
        return await _detail_page(message_id, request, engine, identity)

    @app.get("/ui/messages/{message_id}/summary", response_class=HTMLResponse)
    async def ui_message_detail_summary(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_VIEW_RAW, phi=True)),
    ) -> HTMLResponse:
        return await _detail_page(message_id, request, engine, identity)

    @app.get("/ui/messages/{message_id}/body", response_class=HTMLResponse)
    async def ui_message_detail_body(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_VIEW_RAW, phi=True)),
    ) -> HTMLResponse:
        return await _detail_page(message_id, request, engine, identity)

    @app.get("/ui/messages/{message_id}/errors", response_class=HTMLResponse)
    async def ui_message_detail_errors(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_VIEW_RAW, phi=True)),
    ) -> HTMLResponse:
        return await _detail_page(message_id, request, engine, identity)

    @app.get("/ui/messages/{message_id}/parse-tree", response_class=HTMLResponse)
    async def ui_message_parse_tree(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_VIEW_RAW, phi=True)),
    ) -> HTMLResponse:
        # Reuse the single audited body path (get_message_body, which writes record_view and a
        # message_body_view audit row), then render the tree server-side via the pure parsing lib. The page shows no
        # metadata, so it does not open the message too. Non-HL7 bodies (X12/DICOM/binary) have no
        # HL7 tree — surface that rather than 500. No new PHI egress beyond the audited body fetch.
        # The build and the render run in a worker thread: both are linear in the node count, and
        # the console shares the engine's event loop, so on the loop a large tree would stall every
        # listener and worker for as long as it took (vault BACKLOG #2762). The tree is also capped.
        raw = await _message_body(message_id, request, engine, identity)
        return await asyncio.to_thread(_parse_tree_response, message_id, raw)

    @app.get("/ui/messages/{message_id}/attachments/{attachment_id}")
    async def ui_download_attachment(
        message_id: str,
        attachment_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_VIEW_RAW, phi=True)),
    ) -> Response:
        # Reuse the engine's single audited download path (linkage + channel-scope 404 guard +
        # record_view + attachment_download audit), then hand its Response straight to the browser. A
        # top-level GET nav can't carry the bearer token, so the /ui gate re-asserts view_raw via the
        # session cookie; the engine handler does the same PHI audit as the JSON API route.
        result: Response = await core.download_attachment(
            message_id, attachment_id, engine=engine, identity=identity, request=request
        )
        return result

    @app.get("/ui/dead-letters", response_class=HTMLResponse)
    async def ui_dead_letters(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.MESSAGES_READ, phi=True)),
        # Annotated, not body-validated, unlike ui_messages above: this page carries no filter form.
        # Both values arrive only from a link the console itself built out of a name already in the
        # store, so there is nothing an operator typed to hand back and a 422 is the honest refusal
        # — the same one GET /dead-letters gives for the same two items (BACKLOG #1740).
        channel_id: ConnectionName | None = Query(None),
        destination_name: ConnectionName | None = Query(None),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ) -> HTMLResponse:
        data = await core.list_dead_letters(
            request,
            engine=engine,
            identity=identity,
            # No blank_to_none here, unlike the message log above: the ConnectionName annotation
            # refuses a blank with a 422 before this body runs, so "" never reaches this call
            # (BACKLOG #1740).
            channel_id=channel_id,
            destination_name=destination_name,
            limit=limit,
            offset=offset,
        )
        # The two filters go to the page as well as to the query, because the pager links have to
        # replay them — see ``pages._common._pager`` for why (BACKLOG #1743).
        return HTMLResponse(
            pages.dead_letters(
                data,
                channel_id=channel_id or "",
                destination_name=destination_name or "",
                # The permission ui_message_detail and ui_message_detail_errors require, so the
                # page offers their links only to a caller those routes will answer (BACKLOG #2440).
                can_view_raw=identity.has(Permission.MESSAGES_VIEW_RAW),
            )
        )

    # Safe operator actions (M2): inbound connection start/stop/restart. These reuse the JSON
    # control handlers (require CONNECTIONS_CONTROL + the per-channel _control_guard), and add
    # assert_same_origin as CSRF defense-in-depth on top of the SameSite=Strict cookie (a
    # cross-site POST carries no cookie, so require_ui already 303s). No step-up gate applies to
    # start/stop/restart (unlike replay, which is require_step_up and lands with the browser MFA
    # flow in a later milestone). Each redirects back to the dashboard.
    #
    # All three declare `name: ConnectionName`, the rule /connections/{name}/start declares for the
    # same path segment, so FastAPI answers 422 before the handler runs (BACKLOG #1740). No operator
    # types this: the console renders the name into a form action from the live registry, so only a
    # hand-built URL reaches the refusal and there is no form to send it back to.
    async def _ui_control(
        request: Request,
        name: str,
        engine: Any,
        identity: Identity,
        action: Callable[..., Any],
    ) -> Response:
        assert_same_origin(request)
        # ADR 0150: the console mounts IN-PROCESS on the engine's own app, so this Request is the
        # BROWSER's — forwarding it attributes the row to the operator's host, not the engine.
        await action(name, engine=engine, identity=identity, request=request)
        return RedirectResponse("/ui", status_code=303)

    @app.post("/ui/connections/{name}/start")
    async def ui_start_connection(
        name: ConnectionName,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.CONNECTIONS_CONTROL)),
    ) -> Response:
        return await _ui_control(request, name, engine, identity, core.start_connection)

    @app.post("/ui/connections/{name}/stop")
    async def ui_stop_connection(
        name: ConnectionName,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.CONNECTIONS_CONTROL)),
    ) -> Response:
        return await _ui_control(request, name, engine, identity, core.stop_connection)

    @app.post("/ui/connections/{name}/restart")
    async def ui_restart_connection(
        name: ConnectionName,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui(Permission.CONNECTIONS_CONTROL)),
    ) -> Response:
        return await _ui_control(request, name, engine, identity, core.restart_connection)

    # Sensitive action (M2b): single-message replay. It is require_step_up in the JSON API, so the
    # /ui route uses require_ui_step_up — which, if the session hasn't recently stepped up, 303s the
    # browser to /ui/reauth?next=<this action> instead of returning a 403 header the browser can't
    # act on. After re-auth the browser auto-retries this POST (now inside the step-up window).
    @app.post("/ui/messages/{message_id}/replay")
    async def ui_replay_message(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_REPLAY)),
    ) -> Response:
        assert_same_origin(request)
        await core.replay_message(message_id, engine=engine, identity=identity, request=request)
        # The bare detail path on purpose: a replay is not an act aimed at the summary or the body,
        # so the page it lands on reveals neither (BACKLOG #2346, UI_MESSAGE_REVEALS).
        return RedirectResponse(f"/ui/messages/{message_id}", status_code=303)

    # Resend to an ALTERNATE outbound (ADR 0090 §§1-8, BACKLOG #123/#1500) — ADR 0090's residual (a).
    # The JSON handler's own gate is require_step_up(MESSAGES_RESEND) and nothing else, so these two
    # routes re-assert exactly that. NOT the edit verbs' MESSAGES_VIEW_RAW + phi=True: a resend
    # re-transmits the STORED body and never renders it, so neither page nor response carries PHI.
    # Copying that pair here would charge the per-actor PHI budget for a surface that emits none, and
    # would refuse a role deliberately narrowed to resend-without-read.
    #
    # The confirm page is PLAIN require_ui, and NOT because it is the re-auth continuation: a gated
    # continuation does not loop, since /ui/reauth refreshes the window before it redirects back
    # (BACKLOG #1822 measured it on the uploaded-logs twin, which is now gated). It stays plain
    # because the POST is the step-up-gated act, no JSON route with this method and permission
    # carries a step-up, and the page reads nothing, as the next paragraph says.
    #
    # It reads NO message, which is what lets it stand on `messages:resend` alone. Everything it
    # renders is the operator's own query echoed back through the escaping builders, so it asserts
    # nothing about whether the message exists; the engine handler behind the POST is the single
    # authority on that and 404s outside the caller's channel scope.
    def _spend_on_record(
        request: Request, action: str, *, key: str, to: str | None, rest: str
    ) -> bool:
        """Whether this session spent its proof on an identical request that is still running or
        was kept (vault BACKLOG #2625, ``_auth._SpentForKey``). Lets a gate pass a double-click's
        second POST to its route, which waits for the first and decides. Never under the org
        opt-out, where no proof is spent. The key and the name are checked against their rules
        first."""
        auth = get_auth(request)
        if auth is None or not auth.action_step_up_required:
            return False
        if not _fits_key(key) or (to is not None and not is_connection_name(to)):
            return False
        return proof_spent_for(request, action, _spent_name(request, key, to, rest))

    async def _resend_logged(request: Request) -> bool:
        """Whether ``resend_log`` already holds this resend's key, so the store can only answer it
        as ADR 0090's duplicate (vault BACKLOG #2625). It covers a repeat after a restart, when no
        spend record survives. It matches the key, message and target, not the source, which is
        safe because a duplicate queues nothing. Only the plain resend reads it: a row records no
        actor and no action, and the resend handler renders no body and queues nothing on a
        duplicate. Read at most once per request (kept in the ASGI scope); the gate skips it when
        a spend record already answered. Never under the org opt-out."""
        auth = get_auth(request)
        if auth is None or not auth.action_step_up_required:
            return False
        cache = request.scope.setdefault("mf_2625_repeat", {})
        if "logged" in cache:
            return bool(cache["logged"])
        key = request.query_params.get("idempotency_key", "")
        to = request.query_params.get("to", "")
        answer = False
        if _fits_key(key) and is_connection_name(to):
            prior = await core.prior_resend(
                engine=await deps.get_engine(request),
                idempotency_key=key,
                message_id=request.path_params["message_id"],
                to=to,
            )
            answer = prior is not None
        cache["logged"] = answer
        return answer

    async def _resend_is_repeat(request: Request) -> bool:
        query = request.query_params
        return _spend_on_record(
            request,
            STEP_UP_ACTION_MESSAGE_RESEND,
            key=query.get("idempotency_key", ""),
            to=query.get("to", ""),
            rest=query.get("source", ""),
        ) or await _resend_logged(request)

    @app.get("/ui/messages/{message_id}/resend-confirm", response_class=HTMLResponse)
    async def ui_message_resend_confirm(
        message_id: str,
        to: str = Query(..., min_length=1, max_length=_RESEND_NAME_MAX),
        source: str = Query(..., min_length=1, max_length=_RESEND_NAME_MAX),
        _identity: Identity = Depends(require_ui(Permission.MESSAGES_RESEND)),
    ) -> HTMLResponse:
        # A fresh per-render idempotency token: a repeat of THIS rendered confirm (a double-click)
        # is the ADR 0090 §4 no-op, and asks for no second proof (vault BACKLOG #2625), while
        # re-opening the confirm page mints a new one and is a genuine second resend. It rides the
        # POST's query rather than its body, which is what keeps that POST body-less. It is always
        # minted here: a key in this page's own query is ignored, so a crafted link cannot preload
        # a spent one and turn the operator's resend into a no-op.
        return HTMLResponse(pages.message_resend_confirm(message_id, to, source, uuid4().hex))

    # The resend OUTCOME, reached by the 303 the POST answers a completed resend with
    # (post-redirect-get, vault BACKLOG #2625). A refresh re-renders this GET and sends nothing.
    # Before #2625 the outcome rendered in place on the POST, and a refresh re-POSTed, which was
    # safe only as ADR 0090 §4's no-op. Answering with a GET keeps a refresh from sending anything.
    #
    # Same permission as the POST and nothing more, and it reads no message: the page echoes the
    # outcome the POST put in the query, through the escaping builders and the connection-name
    # rule. A crafted link can therefore show a "queued" page for a resend that never ran. It queues
    # nothing, the audit row is the record, and the detail page is where the delivery shows.
    @app.get("/ui/messages/{message_id}/resend-done", response_class=HTMLResponse)
    async def ui_message_resend_done(
        message_id: str,
        # Echoed from the engine's answer and checked against the connection-name rule, so the
        # page names only what could name a connection. `source` may be absent: a duplicate of a
        # key first used over the JSON API without one reports the prior row's empty source.
        to: Annotated[ConnectionName, Query()],
        source: ConnectionName | None = Query(None),
        duplicate: bool = Query(False),
        _identity: Identity = Depends(require_ui(Permission.MESSAGES_RESEND)),
    ) -> HTMLResponse:
        return HTMLResponse(
            pages.message_resend_done(message_id, to, source or "", duplicate=duplicate)
        )

    # NEITHER OUTCOME GOES TO THE MESSAGE DETAIL PAGE. That page is `require_ui(MESSAGES_VIEW_RAW)`,
    # so redirecting there handed a resend-without-read role a raw JSON 403 in place of every
    # outcome — success and refusal alike — which is exactly the role the permission choice above
    # exists to serve. A refusal re-renders the confirm page in place; a completed resend 303s to
    # the resend-done GET above, which stands on messages:resend alone. That post-redirect-get is
    # what keeps a refresh from re-POSTing (vault BACKLOG #2625).
    @app.post("/ui/messages/{message_id}/resend", response_class=HTMLResponse)
    async def ui_message_resend(
        message_id: str,
        request: Request,
        to: str = Query(..., min_length=1, max_length=_RESEND_NAME_MAX),
        source: str = Query(..., min_length=1, max_length=_RESEND_NAME_MAX),
        idempotency_key: str = Query(..., min_length=1, max_length=128),
        engine: Any = Depends(deps.get_engine),
        # Action-bound, as POST /messages/{id}/resend is (vault BACKLOG #2625).
        # Held, not spent, in the gate: the proof is spent below, after this route's own input
        # check, so a malformed name costs the operator no proof (as on edit-resend).
        identity: Identity = Depends(
            require_ui_step_up_action(
                STEP_UP_ACTION_MESSAGE_RESEND,
                Permission.MESSAGES_RESEND,
                # A missing proof re-opens the CONFIRM page, never this POST path, carrying the
                # selection. The stale key is not carried: the confirm page mints a fresh one.
                reauth_next=_resend_confirm_next,
                spend=False,
                # A double-click's repeat passes without a proof, for the route to decide
                # (vault BACKLOG #2625, _spend_on_record and _resend_logged).
                repeat=_resend_is_repeat,
            )
        ),
    ) -> Response:
        assert_same_origin(request)

        def _refused(notice: str, *, status: int) -> HTMLResponse:
            # Re-render the confirm page carrying the notice, with a FRESH key: the refused attempt
            # never claimed the old one, so reusing it would make the retry look like a duplicate.
            _log.warning("message resend refused: status=%d", status)
            return HTMLResponse(
                pages.message_resend_confirm(message_id, to, source, uuid4().hex, error=notice),
                status_code=400,
            )

        def _refusal_page(exc: HTTPException) -> HTMLResponse | None:
            # All three of 403/404/409 are handled rather than re-raised because an escaping
            # HTTPException renders as application/json inside the HTML console, with the caller's
            # own outbound name quoted in it. The log carries the STATUS only: the message id, the
            # names and `exc.detail` are caller-supplied text, and logging those is log injection.
            notice = _RESEND_NOTICES.get(exc.status_code)
            return None if notice is None else _refused(notice, status=exc.status_code)

        # The Query params carry the LENGTH bounds; the model carries the connection-name RULE
        # (BACKLOG #1108), which the query declarations deliberately do not repeat -- a second copy
        # would be a second definition. So the model can still refuse a value the query accepted, and
        # a `to`/`source` that could not name a connection is refused HERE, before the engine sees it.
        try:
            body = ResendRequest(to=to, idempotency_key=idempotency_key, source=source)
        except ValidationError:
            # Its OWN notice, not the 404 one. Nothing was looked up, so "was not found" would send
            # the operator hunting on /ui/connections for a connection whose real problem is that the
            # name could not name one.
            return _refused(RESEND_MALFORMED_NOTICE, status=400)
        # The engine handler's own action-bound gate does not run on a direct call, so the proof
        # the gate above only checked is spent here, immediately before the resend, and tied to
        # this request. A repeat (a double-click) spends nothing: spend_ui_action_step_up waits
        # for the first and rides on it unless the handler refused it. The handler still runs a
        # rider, for the channel-scope and target checks and a truthful outcome, and the store
        # answers a committed key as ADR 0090 §4's duplicate. A target that has since gone down
        # answers 409 instead.
        # A key resend_log already holds needs no spend: the store answers it as a duplicate.
        try:
            spend = (
                None
                if await _resend_logged(request)
                else await spend_ui_action_step_up(
                    request,
                    STEP_UP_ACTION_MESSAGE_RESEND,
                    reauth_next=_resend_confirm_next,
                    key=_spent_name(request, body.idempotency_key, body.to, source),
                    identity=identity,
                )
            )
        except RepeatRefused as repeat:
            # A double-click whose first POST the handler refused: the same answer, nothing run.
            page = _refusal_page(repeat.refusal)
            if page is None:
                first = repeat.refusal
                raise HTTPException(first.status_code, first.detail, first.headers) from None
            return page
        try:
            result = await core.resend_message(
                message_id, body=body, request=request, engine=engine, identity=identity
            )
        except HTTPException as exc:
            # A refusal drops the spend record, so the next submit asks for a proof again, and
            # answers a repeat waiting on it with this same refusal.
            settle_ui_action_step_up(spend, refused=True, refusal=exc)
            page = _refusal_page(exc)
            if page is None:
                raise
            return page
        finally:
            # Any other way out keeps the record, a cancel after the store committed included
            # (_auth._SpentForKey says why). A no-op after the refusal above.
            settle_ui_action_step_up(spend, refused=False)
        # `duplicate` means the key was already used and NOTHING was queued (ADR 0090 §4). Reporting
        # it as a send would be the same lie as answering a refusal with the success response.
        echo = {"to": result.to, "source": result.source} if result.source else {"to": result.to}
        outcome = urlencode(
            {**echo, "duplicate": "true" if result.status == "duplicate" else "false"}
        )
        return RedirectResponse(
            f"/ui/messages/{_seg(message_id)}/resend-done?{outcome}", status_code=303
        )

    # Edit-and-resubmit (ADR 0090 §9, BACKLOG #153). GET renders the editor (a COPY of the raw); the
    # step-up gate opens it inside a fresh window (unlock continuation). The origin row is only READ
    # here (the audited get_message and get_message_body paths); nothing is written until the operator
    # POSTs /edit-resend.
    #
    # view_raw is required ALONGSIDE edit (BACKLOG #324) because the editor inherently DISPLAYS the
    # body: it renders the fetched body into the textarea and ships a second pristine copy in
    # `data-original`. `messages:edit` stays mintable on a custom role (ADR 0045 D1 is unchanged), so
    # without this a role meaning "may resubmit, must not read" would read raw PHI here — the read
    # permission its grant deliberately withheld. Such a role is still mintable and still resubmits
    # via the API; it simply cannot open this editor, which is correct: you cannot edit-and-resend
    # without seeing what you are editing. phi=True charges the per-actor PHI-read budget, matching
    # the sibling raw views above (message detail, parse-tree, attachment download).
    @app.get("/ui/messages/{message_id}/edit", response_class=HTMLResponse)
    async def ui_message_edit(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        # The edit-resend grant must be HELD to open the editor, and is not spent here (vault BACKLOG
        # #2625). Asked at submit time instead, the re-auth would re-open this page and drop the edit.
        identity: Identity = Depends(
            require_ui_step_up_action(
                STEP_UP_ACTION_MESSAGE_EDIT_RESEND,
                Permission.MESSAGES_EDIT,
                Permission.MESSAGES_VIEW_RAW,
                phi=True,
                spend=False,
            )
        ),
    ) -> HTMLResponse:
        detail = await _open_message(message_id, request, engine, identity)
        raw = await _message_body(message_id, request, engine, identity)
        # A fresh per-open idempotency token: a double-submit of THIS rendered form is an idempotent
        # no-op; re-opening the editor mints a new token (a genuine second resubmit).
        return HTMLResponse(pages.message_edit(detail, uuid4().hex, original=raw))

    # Same two-permission gate as the GET (BACKLOG #324), because this verb ALSO renders the body: the
    # `_reject` arm below re-reads the origin via the audited `core.get_message_body` and re-ships the
    # PRISTINE stored copy through `data_original`. Gating it on `messages:edit` alone would leave the
    # rejection path as an unauthorized read of exactly the body the GET now refuses. phi=True for the
    # same reason — otherwise the reject path is an UNTHROTTLED channel for re-reading stored bodies
    # while the equivalent GET is throttled.
    async def _resubmit_form(request: Request) -> dict[str, str]:
        """The urlencoded resubmit form, parsed once per request and kept in the ASGI scope for the
        gate's repeat check and the route alike. Stdlib, because the engine has no
        python-multipart dependency, so ``request.form()`` would fail."""
        cache = request.scope.setdefault("mf_2625", {})
        cached = cache.get("form")
        if isinstance(cached, dict):
            return cached
        form = dict(parse_qsl((await request.body()).decode("utf-8", "replace")))
        cache["form"] = form
        return form

    async def _resubmit_is_repeat(request: Request) -> bool:
        auth = get_auth(request)
        if auth is None or not auth.action_step_up_required:
            return False  # no proof is spent under the opt-out, so hash nothing
        form = await _resubmit_form(request)
        key = str(form.get("idempotency_key", "")).strip()
        if not _fits_key(key):
            return False
        direct = str(form.get("mode", "reroute")) == "direct"
        return _spend_on_record(
            request,
            STEP_UP_ACTION_MESSAGE_EDIT_RESEND,
            key=key,
            to=str(form.get("to", "")).strip() if direct else None,
            rest=_body_digest(request, str(form.get("raw", ""))),
        )

    @app.post("/ui/messages/{message_id}/edit-resend")
    async def ui_message_edit_resend(
        message_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        # Held, not spent, in the gate (vault BACKLOG #2625): the grant is spent below, after this
        # route's own input checks, so a refusal of those (direct mode with no outbound, an invalid
        # body) costs the operator no proof. A refusal from the engine handler comes after the
        # spend, so the next submit asks again and re-opens the editor from the stored body.
        identity: Identity = Depends(
            require_ui_step_up_action(
                STEP_UP_ACTION_MESSAGE_EDIT_RESEND,
                Permission.MESSAGES_EDIT,
                Permission.MESSAGES_VIEW_RAW,
                phi=True,
                # A missing proof on this body-carrying POST re-opens the /edit form, never the
                # POST path (a re-POST would drop the edited body).
                reauth_next=_edit_page,
                spend=False,
                # A double-click's repeat passes without a proof, for the route to decide
                # (vault BACKLOG #2625, _spend_on_record).
                repeat=_resubmit_is_repeat,
            )
        ),
    ) -> Response:
        assert_same_origin(request)
        form = await _resubmit_form(request)
        raw = str(form.get("raw", ""))
        idem = str(form.get("idempotency_key", "")).strip()
        mode = str(form.get("mode", "reroute"))
        to = str(form.get("to", "")).strip()

        async def _reject(msg: str) -> HTMLResponse:
            # Re-render the editor preserving the operator's edits (raw_value) AND their destination
            # choice (mode + to) — so a rejected direct send doesn't silently reset to re-route and drop
            # the typed outbound (review #153-4). The audited get_message_body re-read is the same PHI path
            # the GET used. NEVER echo the edited body in the error text.
            detail = await _open_message(message_id, request, engine, identity)
            original = await _message_body(message_id, request, engine, identity)
            return HTMLResponse(
                pages.message_edit(
                    detail,
                    idem or uuid4().hex,
                    original=original,
                    raw_value=raw,
                    error=msg,
                    mode=mode,
                    to=to,
                ),
                status_code=400,
            )

        if mode == "direct" and not to:
            return await _reject(
                "choose an outbound connection for a direct send, or re-route instead"
            )
        try:
            body = EditResendRequest(
                raw=raw,
                idempotency_key=idem,
                reroute=(mode != "direct"),
                to=(to if mode == "direct" else None),
            )
        except ValidationError:
            # PHI-safe: a bad edited body must never be echoed — a generic message only.
            return await _reject("invalid input")
        # The engine handler's own action-bound gate does not run on a direct call, so the grant
        # the gate above only checked is spent here, immediately before the resubmit, and tied to
        # this request. A repeat (a double-click) spends nothing: spend_ui_action_step_up waits
        # for the first and rides on it unless the handler refused it. The store answers a
        # committed key as a duplicate and the route lands where the first one did.
        try:
            spend = await spend_ui_action_step_up(
                request,
                STEP_UP_ACTION_MESSAGE_EDIT_RESEND,
                reauth_next=_edit_page,
                key=_spent_name(request, body.idempotency_key, body.to, _body_digest(request, raw)),
                identity=identity,
            )
        except RepeatRefused as repeat:
            # A double-click whose first POST the handler refused: the same answer, with the
            # operator's edit kept in the editor, and nothing run.
            return await _reject(str(repeat.refusal.detail))
        try:
            result = await core.edit_resend_message(
                message_id, body=body, engine=engine, identity=identity, request=request
            )
        except HTTPException as exc:
            # A refused resubmit drops its spend record BEFORE the two audited reads in _reject,
            # so a repeat waiting on it is answered at once, and the editor _reject re-renders
            # with the same key asks for a proof again on the next submit.
            settle_ui_action_step_up(spend, refused=True, refusal=exc)
            # str(exc.detail) carries ids only (the endpoint never interpolates the body).
            return await _reject(str(exc.detail))
        finally:
            # Any other way out keeps the record, a cancel after the store committed included:
            # edit-resend has no resend_log to fall back on, so dropping it here sent the retry
            # to re-auth (_auth._SpentForKey). A no-op after the refusal above.
            settle_ui_action_step_up(spend, refused=False)
        # Land on the NEW correlated child (re-route) so the operator sees the resubmit flow; the direct
        # path lands back on the origin (which now carries the new outbound row). The ORIGINAL is intact.
        target = result.new_message_id if (result.reroute and result.new_message_id) else message_id
        return RedirectResponse(f"/ui/messages/{target}", status_code=303)

    async def _reauth_webauthn_state(
        request: Request,
        auth: AuthService,
        token: str | None,
        mfa: MfaStatus,
        satisfied: bool,
    ) -> tuple[str | None, str | None]:
        """(assertion-options JSON, fail-closed notice) for the reauth page's passkey leg.

        Options are freshly staged per render (the prior challenge is single-use — ADR 0068
        decision 1(e): the passkey button must survive a failed password/code attempt). The
        notice is the legible dead-end copy when ceremonies can't run (extra absent /
        rp unavailable) — never a redirect loop."""
        if satisfied or not mfa.webauthn_enrolled:
            return None, None
        if not auth.webauthn_available():
            return None, WEBAUTHN_EXTRA_MISSING_NOTICE
        rp = webauthn_rp(request)
        if rp is None:
            return None, WEBAUTHN_RP_MISSING_NOTICE
        options = await auth.begin_webauthn_assertion(token, rp_id=rp[0])
        if options is None:
            # Enrolled, but every credential was minted under a DIFFERENT rp_id (the
            # origin-migration case, ADR 0068 §7) — a legible dead-end naming the
            # admin-reset recovery, never a bare password form with a misleading
            # "complete the passkey prompt" error (PR-A review finding).
            return None, WEBAUTHN_RP_CHANGED_NOTICE
        return options, None

    async def _reauth_idp_page(
        auth: AuthService,
        token: str | None,
        mfa: MfaStatus,
        next_: str,
        step_up: bool,
        continues: bool,
    ) -> Response:
        """/ui/reauth for a session the federated login minted (BACKLOG #296).

        Runs BEFORE the password page's enroll-first bounce, because that bounce keys on the account
        (``mfa.required``, nothing enrolled) and an OIDC session minted with the IdP's MFA claim has
        met its factor without any engine enrollment. Only a session that has NOT met it is routed:
        one owing an ENROLLED engine factor proves it at the MFA gate first (the IdP leg re-proves
        the sign-in, not the engine's factor), and one that owes a factor it has not enrolled goes
        to enroll for a full step-up action, as the password page sends it."""
        if not await auth.mfa_satisfied(token):
            if mfa.enabled or mfa.webauthn_enrolled:
                return RedirectResponse("/ui/mfa", status_code=303)
            if step_up:
                # Keyed on "not satisfied", not on the account rule mfa.required: the directory
                # floor can leave a session unsatisfied that the account rule calls exempt, and
                # the step-up gate asks the session.
                return RedirectResponse("/ui/account?m=enroll_first", status_code=303)
        return reauth_idp_response(deps, auth, next_, continues=continues)

    async def _mfa_gate_deadline(auth: AuthService, identity: Identity) -> float | None:
        """The temporary credential's deadline for /ui/mfa, or ``None`` (BACKLOG #2009, ASVS 6.4.5).

        A must-change holder with a second factor answers it here before reaching the forced
        password page, so this page states the deadline too, from the source that page reads. The
        flag check keeps the store read off every other account's gate."""
        if not identity.must_change_password:
            return None
        return await pending_credential_deadline_for(auth, identity.user_id)

    @app.get("/ui/mfa", response_class=HTMLResponse)
    @public_route("the second-factor page for a session the gates refuse until it verifies")
    async def ui_mfa_form(request: Request) -> Response:
        """The ASVS 6.3.3 confinement page for an MFA-pending browser session.

        Carries NO ``require_ui`` dependency on purpose — the gate 303s every pending session here, so
        a gated version of this page would redirect to itself. Auth is done by hand instead, in the
        SAME order the gate uses, so the two cannot disagree.

        A separate route rather than a reuse of ``/ui/reauth``: that page 303s to /ui unless ``next``
        names a registered write action, and its POST always demands the password — which an operator
        proved seconds earlier at sign-in.
        """
        auth = get_auth(request)
        token = session_token(request)
        identity = await auth.identity_for_token(token) if auth is not None else None
        if auth is None or identity is None:
            return login_redirect_response()
        if await rotation_comes_first(auth, identity.must_change_password, token):
            # must_change outranks MFA for an account with no factor, mirroring require()/require_ui:
            # a fresh account is both, and only rotation is reachable until it happens. One that
            # still owes an enrolled factor stays here to answer it (BACKLOG #1954), and one that
            # must enrol TOTP first never reaches this branch (rotation_comes_first is False).
            return RedirectResponse("/ui/account/password", status_code=303)
        if await auth.mfa_satisfied(token):
            return RedirectResponse("/ui", status_code=303)  # idempotent: nothing owed
        mfa = await auth.mfa_status(identity)
        if not (mfa.enabled or mfa.webauthn_enrolled):
            # Required but NOTHING enrolled: there is no factor to ask for. Reuse the existing
            # enroll-first bounce rather than rendering a form that cannot be answered — this is
            # what keeps a fresh account from bouncing between the gate and an empty page.
            return RedirectResponse("/ui/account?m=enroll_first", status_code=303)
        wa_options, wa_notice = await _reauth_webauthn_state(request, auth, token, mfa, False)
        return HTMLResponse(
            pages.mfa_gate(
                totp_enrolled=mfa.enabled,
                webauthn_options=wa_options,
                webauthn_notice=wa_notice,
                credential_expires_at=await _mfa_gate_deadline(auth, identity),
            )
        )

    @app.post("/ui/mfa")
    @public_route("the second-factor check for a session the gates refuse until it verifies")
    async def ui_mfa_submit(request: Request) -> Response:
        assert_same_origin(request)
        auth = get_auth(request)
        token = session_token(request)
        identity = await auth.identity_for_token(token) if auth is not None else None
        if auth is None or not token or identity is None:
            return login_redirect_response()
        if await rotation_comes_first(auth, identity.must_change_password, token):
            return RedirectResponse("/ui/account/password", status_code=303)
        client = request.client.host if request.client else None
        if not allow_reauth_attempt(auth, identity, client):
            # Same per-ACTOR ceremony budget the reauth/password flows draw on, so code-guessing
            # here cannot outrun it either.
            # Retry-After: 30 matches POST /ui/reauth, the sibling ceremony on the SAME per-actor
            # budget — a different hint for the same limiter would just misreport when it clears.
            raise HTTPException(429, "too many attempts", headers={"Retry-After": "30"})
        form = dict(parse_qsl((await request.body()).decode("utf-8", "replace")))
        elevation = await auth.verify_mfa(token, form.get("code", ""), client=client)
        if elevation.token is not None:
            # The session was re-keyed (ASVS 7.2.4), so the cookie this browser holds is now dead.
            # Re-set it on the redirect or the operator is signed out by their own correct code. A
            # must-change session proved its factor first and rotates next (BACKLOG #1954).
            target = "/ui/account/password" if identity.must_change_password else "/ui"
            resp = RedirectResponse(target, status_code=303)
            rekey_continuations(token, elevation.token)  # vault BACKLOG #2764
            set_session_cookie(resp, elevation.token, request=request)
            return resp
        if elevation.session_lost:
            # A correct code on a session revoked underneath it: there is nothing to re-render the
            # gate for, and the cookie is dead. Land on login like any other post-termination exit.
            return login_redirect_response()
        mfa = await auth.mfa_status(identity)
        wa_options, wa_notice = await _reauth_webauthn_state(request, auth, token, mfa, False)
        # The submitted code is NOT echoed back — it is a bearer credential, and verify_mfa has
        # already audited the failure. Generic copy: the form cannot say whether the code was
        # wrong or expired without narrowing a guess. A directory refusal narrows nothing, because
        # the code was never checked (BACKLOG #2023), so it says what did happen.
        return HTMLResponse(
            pages.mfa_gate(
                totp_enrolled=mfa.enabled,
                error=(
                    _DIRECTORY_UNCONFIRMED_ERROR
                    if _directory_unconfirmed(elevation)
                    else "That code wasn't accepted. Try again."
                ),
                webauthn_options=wa_options,
                webauthn_notice=wa_notice,
                credential_expires_at=await _mfa_gate_deadline(auth, identity),
            ),
            status_code=400,
        )

    @app.get("/ui/reauth", response_class=HTMLResponse)
    @public_route("the re-authentication page a step-up gate sends the browser to")
    async def ui_reauth_form(
        request: Request,
        next_: str = Query("", alias="next", max_length=512),
    ) -> Response:
        # next MUST be a registered /ui action — a body-less POST the re-auth may auto-retry
        # (is_safe_ui_action) OR a GET admin form page it may unlock (is_unlock_action). Never an
        # arbitrary URL (anti open-redirect) — an unregistered next bounces to /ui.
        action = lookup_ui_action(next_)
        if action is None:
            return RedirectResponse("/ui", status_code=303)
        auth = get_auth(request)
        token = session_token(request)
        # Vault BACKLOG #2764: an auto-retry action continues after the confirmation only when a
        # step-up gate issued it to THIS session. Any other `next` still gets the form, which names
        # the action and says nothing will run; the POST then ends on a page saying nothing ran.
        continues = continues_after_reauth(action, token, next_)
        identity = await auth.identity_for_token(token) if auth is not None else None
        if auth is None or identity is None:
            # The session ended under the operator (expiry / revoke) — a post-termination landing
            # like any other, so it carries Clear-Site-Data + the explanatory code (14.3.1).
            return login_redirect_response()
        if identity.must_change_password and not await auth.must_enrol_before_rotating(identity):
            # Mirror require_ui's confinement (L4b): rotate, or first prove an owed factor (#1954).
            # A session that must enrol before rotating (ADR 0197 Amendment A) re-proves its
            # password here to reach the TOTP enrolment, so it is let through.
            return RedirectResponse(await must_change_target(auth, token), status_code=303)
        mfa = await auth.mfa_status(identity)
        if await auth.session_steps_up_at_idp(token):
            # BACKLOG #296, ADR 0142 Amendment B: a session the federated login minted steps up at
            # the IdP, so this page renders NO password field at all. Decided by the SESSION's
            # mechanism, not the account: a Kerberos session keeps the password form below.
            # Ahead of the enroll-first bounce; _reauth_idp_page says why.
            return await _reauth_idp_page(auth, token, mfa, next_, action.step_up, continues)
        if mfa.required and not (mfa.enabled or mfa.webauthn_enrolled) and action.step_up:
            # A full-step-up action a required-but-UNENROLLED session (no factor of EITHER
            # kind — ADR 0068 decision 1(a)) can NEVER satisfy — send it to enroll instead
            # of a password form that would loop straight back. Enrollment itself is
            # step_up=False (below).
            return RedirectResponse("/ui/account?m=enroll_first", status_code=303)
        # The rendering splits BY FACTOR (decision 1(b)): the TOTP code field renders iff
        # TOTP is enrolled (a required-but-unenrolled account can never produce a code —
        # demanding one would deadlock, L4b); the passkey hook renders iff WebAuthn is
        # enrolled — a WebAuthn-only user sees password + passkey, never an unanswerable
        # code field; a both-enrolled user sees both, either satisfies.
        satisfied = await auth.mfa_satisfied(token)
        mfa_needed = not satisfied and mfa.enabled
        wa_options, wa_notice = await _reauth_webauthn_state(request, auth, token, mfa, satisfied)
        return HTMLResponse(
            pages.reauth(
                next_,
                label=action.label,
                continues=continues,
                mfa_needed=mfa_needed,
                webauthn_options=wa_options,
                webauthn_notice=wa_notice,
            )
        )

    @app.post("/ui/reauth")
    @public_route("the re-authentication a step-up gate sends the browser to")
    async def ui_reauth(request: Request) -> Response:
        assert_same_origin(request)
        auth = get_auth(request)
        token = session_token(request)
        identity = await auth.identity_for_token(token) if auth is not None else None
        if auth is None or not token or identity is None:
            return login_redirect_response()  # session ended mid-ceremony — see ui_reauth_form
        if identity.must_change_password and not await auth.must_enrol_before_rotating(identity):
            # Mirror require_ui's confinement (L4b): rotate, or first prove an owed factor (#1954).
            # A session that must enrol before rotating (ADR 0197 Amendment A) re-proves its
            # password here to reach the TOTP enrolment, so it is let through.
            return RedirectResponse(await must_change_target(auth, token), status_code=303)
        form = dict(parse_qsl((await request.body()).decode("utf-8", "replace")))
        next_ = form.get("next", "")
        action = lookup_ui_action(next_)
        if action is None:
            return RedirectResponse("/ui", status_code=303)
        if await auth.session_steps_up_at_idp(token):
            # BACKLOG #296: never verify a password (or rotate on a code) for an OIDC session. Its
            # step-up is the IdP leg that GET /ui/reauth renders, so send the browser there without
            # reading the password. No audit row is written here; the service's reauth() refuses
            # such a session too, and it is the one that audits reason=idp_step_up_required.
            return RedirectResponse("/ui/reauth?" + urlencode({"next": next_}), status_code=303)
        mfa = await auth.mfa_status(identity)
        # continues_after_reauth is asked of `token` at each use, not once here: the code leg below
        # rotates it and re-keys the issued continuation onto the new token.
        if mfa.required and not (mfa.enabled or mfa.webauthn_enrolled) and action.step_up:
            # See ui_reauth_form: a full-step-up action this session can never satisfy (no
            # factor of EITHER kind — ADR 0068 decision 1(a)) — send it to enroll rather
            # than loop. Checked BEFORE the rate limiter so a correct password isn't burned
            # into a 429 (the review's silent-loop finding; the ordering pin covers the
            # generalized condition too).
            return RedirectResponse("/ui/account?m=enroll_first", status_code=303)
        satisfied = await auth.mfa_satisfied(token)
        if not satisfied and not mfa.enabled and mfa.webauthn_enrolled:
            # ADR 0068 decision 1(d): a WebAuthn-ONLY user's password form can never satisfy
            # MFA by itself — the passkey leg (POST /ui/reauth/webauthn) must run first.
            # Checked BEFORE the rate limiter (parallel to the anti-loop check) so a
            # password-first submission burns no limiter slot and no password verify runs
            # before the ceremony. Never "Invalid code." — the user has no code to type.
            wa_options, wa_notice = await _reauth_webauthn_state(
                request, auth, token, mfa, satisfied
            )
            return HTMLResponse(
                pages.reauth(
                    next_,
                    label=action.label,
                    continues=continues_after_reauth(action, token, next_),
                    mfa_needed=False,
                    webauthn_options=wa_options,
                    webauthn_notice=wa_notice,
                    error=wa_notice
                    or "Complete the passkey prompt first, then re-enter your password.",
                ),
                status_code=400,
            )
        client = request.client.host if request.client else None
        if not allow_reauth_attempt(auth, identity, client):  # per-ACTOR, not the sign-in budget
            raise HTTPException(429, "too many attempts", headers={"Retry-After": "30"})

        # Satisfy whichever factor is pending — TOTP first (mirrors require_step_up), then
        # password. The code is only demanded from a user with an ENROLLED authenticator
        # (decision 1(c): the code branch keys on TOTP enrollment alone — a WebAuthn-only
        # user is never asked for a code): a required-but-unenrolled account reaches this
        # page on its way to enrolling (L4b) and has nothing to type — its enrollment routes
        # gate on the password step-up alone (require_ui_reauth_only), exactly like the JSON
        # require_reauth_only. Error re-renders re-stage FRESH assertion options (decision
        # 1(e)): the prior challenge was single-use, and the passkey button must survive a
        # failed password/code attempt.
        # THIS HANDLER CAN ROTATE TWICE IN ONE REQUEST — the code leg below, then the password leg.
        # Two consequences, and both are load-bearing:
        #  1. `token` is REBOUND after each rotation. The second call must run against the live hash;
        #     against the retired one it fails closed and a correct password reads as wrong.
        #  2. EVERY return path past the first rotation re-sets the cookie, the error exits included.
        #     A correct code followed by a wrong password rotates once and then renders an error page;
        #     without the cookie on that response the browser would be left holding a dead cookie in
        #     the middle of the ceremony, which presents as an unexplained sign-out.
        def _keep_session(resp: Response, tok: str) -> Response:
            """Carry the session's CURRENT token onto an outgoing response.

            Takes the token as an argument rather than closing over it: a closure would capture the
            variable, and the whole point here is that it is rebound mid-handler."""
            set_session_cookie(resp, tok, request=request)
            return resp

        mfa_enrolled = mfa.enabled
        if mfa_enrolled and not satisfied:
            code = form.get("code", "").strip()
            code_elevation = (
                await auth.verify_mfa(token, code, client=client) if code else Elevation()
            )
            if code_elevation.session_lost:
                return login_redirect_response()  # session ended under a correct code
            if code_elevation.token is not None:
                rekey_continuations(token, code_elevation.token)
                token = code_elevation.token  # rotation 1 of 2
            else:
                wa_options, wa_notice = await _reauth_webauthn_state(
                    request, auth, token, mfa, await auth.mfa_satisfied(token)
                )
                # Nothing rotated on this leg, so the cookie the browser holds is still live.
                return HTMLResponse(
                    pages.reauth(
                        next_,
                        label=action.label,
                        continues=continues_after_reauth(action, token, next_),
                        mfa_needed=True,
                        webauthn_options=wa_options,
                        webauthn_notice=wa_notice,
                        error=(
                            "Account locked. Try again later."
                            if code_elevation.locked
                            else _DIRECTORY_UNCONFIRMED_ERROR
                            if _directory_unconfirmed(code_elevation)
                            else "Invalid code."
                        ),
                    )
                )
        # 7.5.1 (ADR 0077): mint the single-use grant bound to this continuation's action.
        # action.action is None for a continuation whose route rides the session window (replay,
        # create-user and the like), so reauth mints nothing there. The factor-binding lanes tag their
        # action, and so, since vault BACKLOG #2625, do the purge, reload, resend, edit-resend and
        # upload-resend continuations.
        # Vault BACKLOG #2764: only for a continuation that will run. A `next` the console did not
        # issue to this session takes no grant, because ADR 0077 derives the grant's purpose from
        # `next` itself, and a forged one would otherwise bind the proof to the forged action.
        pre_rotation = token
        pw_elevation = await auth.reauth(
            identity,
            form.get("password", ""),
            token=token,
            client=client,
            purpose=action.action if continues_after_reauth(action, token, next_) else None,
        )
        if pw_elevation.session_lost:
            return login_redirect_response()
        if pw_elevation.idp_step_up_required:
            # BACKLOG #296. Unreachable while the early redirect above holds; kept so a reordering
            # sends the operator to the IdP leg instead of reporting a correct password as wrong.
            return _keep_session(
                RedirectResponse("/ui/reauth?" + urlencode({"next": next_}), status_code=303),
                token,
            )
        if pw_elevation.token is None:
            still_unsatisfied = not await auth.mfa_satisfied(token)
            wa_options, wa_notice = await _reauth_webauthn_state(
                request, auth, token, mfa, not still_unsatisfied
            )
            # The wrong-password exit AFTER a successful code leg — the stranded-cookie case. A
            # directory that could not judge the password never called it wrong (BACKLOG #2027).
            return _keep_session(
                HTMLResponse(
                    pages.reauth(
                        next_,
                        label=action.label,
                        continues=continues_after_reauth(action, token, next_),
                        mfa_needed=mfa_enrolled and still_unsatisfied,
                        webauthn_options=wa_options,
                        webauthn_notice=wa_notice,
                        error=(
                            _DIRECTORY_UNCONFIRMED_ERROR
                            if _directory_unconfirmed(pw_elevation)
                            else "Incorrect password."
                        ),
                    )
                ),
                token,
            )
        token = pw_elevation.token  # rotation 2 of 2
        # Fully stepped up. Hand control back per the action's continuation style:
        #  - an unlock target is a GET admin form: 303-GET-redirect so it re-opens inside the now
        #    fresh window; the operator then submits the body-carrying POST (incl. a create-user
        #    password) once, never crossing /ui/reauth (the stateless confirm-after-step-up path).
        #  - a body-less POST action the console issued to this session: auto-retry it via the
        #    same-origin submit form, spending the issue so it auto-submits once (#2764).
        #  - any other body-less POST action: a page that says nothing ran, so an operator whose
        #    entry lapsed (TTL, restart, eviction) does not read the landing as the action done.
        # The issue is spent under the pre-rotation token, the key it still sits under, and then
        # the session's OTHER issued entries follow the rotation -- before any branch returns, so
        # an unlock re-auth in one tab does not strand an action another tab is confirming.
        issued = not action.unlock and consume_continuation(pre_rotation, next_)
        rekey_continuations(pre_rotation, token)
        if is_unlock_action(next_):
            return _keep_session(RedirectResponse(next_, status_code=303), token)
        if issued:
            return _keep_session(HTMLResponse(pages.reauth_continue(next_, action.label)), token)
        return _keep_session(
            HTMLResponse(pages.reauth_nothing_ran(action.label, reauth_landing(identity))), token
        )

    # ADR 0068 decision 6: the browser passkey leg of step-up. A cookie-authed JSON POST
    # (the sanctioned /ui carve — the cookie stays confined to /ui deps; bearer_token()
    # is untouched) that verifies an assertion and stamps the session's MFA leg ONLY —
    # the operator still submits POST /ui/reauth (password) for reauth_at + the WP-L3-13
    # client re-anchor. NOT registered as a continuation (body-carrying JSON — part of the
    # step-up mechanism itself). MFA-pending sessions pass (the assertion IS the proof);
    # must-change confinement is mirrored manually like /ui/mfa's, NOT like both /ui/reauth
    # handlers: a must-change session that still owes its factor must pass. For a passkey-only
    # account this is the only way to prove it (BACKLOG #1954).
    @app.post("/ui/reauth/webauthn")
    @public_route("the passkey re-authentication a step-up gate sends the browser to")
    async def ui_reauth_webauthn(request: Request) -> Response:
        assert_same_origin(request)
        auth = get_auth(request)
        token = session_token(request)
        identity = await auth.identity_for_token(token) if auth is not None else None
        if auth is None or not token or identity is None:
            return JSONResponse({"ok": False, "error": "session expired"}, status_code=401)
        if await confined_before_its_factor(auth, identity.must_change_password, token):
            # Mirror /ui/mfa's confinement (L4b). A session that must enrol before rotating (ADR 0197
            # Amendment A) stays confined here too: it has no passkey to prove.
            return JSONResponse({"ok": False, "error": "password change required"}, status_code=403)
        rp = webauthn_rp(request)
        if rp is None:
            return JSONResponse({"ok": False, "error": "rp_unavailable"}, status_code=409)
        client = request.client.host if request.client else None
        if not allow_reauth_attempt(auth, identity, client):  # per-ACTOR, not the sign-in budget
            return JSONResponse(
                {"ok": False, "error": "too many attempts"},
                status_code=429,
                headers={"Retry-After": "30"},
            )
        try:
            body = await request.json()
            response_json = json.dumps(body["response"])
        except (ValueError, KeyError, TypeError):
            return JSONResponse({"ok": False, "error": "malformed request"}, status_code=400)
        elevation = await auth.finish_webauthn_assertion(
            token, response_json, client=client, rp_id=rp[0], origin=rp[1]
        )
        if elevation.session_lost:
            return JSONResponse({"ok": False, "error": "session expired"}, status_code=401)
        if elevation.token is None:
            # BACKLOG #2239: the directory could not vouch for a directory account, so the
            # assertion was never checked and "verification failed" would be false.
            error = (
                _DIRECTORY_UNCONFIRMED_ERROR
                if _directory_unconfirmed(elevation)
                else "passkey verification failed"
            )
            return JSONResponse({"ok": False, "error": error}, status_code=400)
        # The assertion re-keyed the session (ASVS 7.2.4). The new cookie rides this JSON response,
        # because the page's next request is the POST /ui/reauth password leg — it would otherwise
        # present the retired token and be refused on a correct password.
        # The rotation re-keys the session, so the continuation this page was issued moves with it
        # (vault BACKLOG #2764); otherwise the password leg would find nothing to continue.
        rekey_continuations(token, elevation.token)
        resp = JSONResponse({"ok": True})
        set_session_cookie(resp, elevation.token, request=request)
        return resp

    # Bulk dead-letter replay (M3): re-queue ALL dead deliveries for one channel. Like message
    # replay it is require_step_up (→ require_ui_step_up, which 303s to /ui/reauth on a stale
    # step-up; the channel is in the PATH so the auto-retry re-POST carries it — no lost body).
    # Reuses the JSON replay_dead_letters handler, so the dual-control approval gate applies: when
    # it holds the op for a second approver, surface that instead of redirecting.
    async def _ui_dl_replay(
        request: Request,
        channel_id: str | None,
        destination_name: str | None,
        engine: Any,
        identity: Identity,
        gate: Any,
    ) -> Response:
        assert_same_origin(request)
        # channel_id=None ⇒ every channel (the all-channels scope, L6b); the JSON handler
        # pre-checks scope and refuses a channel-scoped user before mutating anything.
        result = await core.replay_dead_letters(
            DeadLetterReplayRequest(channel_id=channel_id, destination_name=destination_name),
            Response(),
            engine=engine,
            identity=identity,
            gate=gate,
            request=request,
        )
        if isinstance(result, PendingApprovalResponse):
            return HTMLResponse(pages.dead_letter_pending(result))
        return RedirectResponse("/ui/dead-letters", status_code=303)

    # L6b (#75 parity): replay ALL dead deliveries across every channel in one action (the
    # desktop's null-scope "Replay all"). Declared before the {channel_id} routes; the
    # literal `replay-all` can't be a channel id (it has no `/replay` suffix). Same
    # step-up + dual-control gate; the JSON handler still denies channel-scoped users.
    @app.post("/ui/dead-letters/replay-all")
    async def ui_replay_all_dead_letters(
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_REPLAY)),
        gate: Any = Depends(deps.get_gate),
    ) -> Response:
        return await _ui_dl_replay(request, None, None, engine, identity, gate)

    @app.post("/ui/dead-letters/{channel_id}/replay")
    async def ui_replay_dead_letters(
        channel_id: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_REPLAY)),
        gate: Any = Depends(deps.get_gate),
    ) -> Response:
        # All dead deliveries for the channel (every destination).
        return await _ui_dl_replay(request, channel_id, None, engine, identity, gate)

    @app.post("/ui/dead-letters/{channel_id}/{destination_name}/replay")
    async def ui_replay_dead_letters_dest(
        channel_id: str,
        destination_name: str,
        request: Request,
        engine: Any = Depends(deps.get_engine),
        identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_REPLAY)),
        gate: Any = Depends(deps.get_gate),
    ) -> Response:
        # Just the dead deliveries for this (channel, destination).
        return await _ui_dl_replay(request, channel_id, destination_name, engine, identity, gate)

    @app.post("/ui/csp-report")
    @public_route("browsers send CSP violation reports without a session")
    async def ui_csp_report(request: Request) -> Response:
        # ASVS 3.5.1 — FIRST statement. The THIRD unguarded /ui POST is disposed of here, with the
        # NARROW guard rather than the full same-origin check, because the two are not interchangeable
        # on a report sink: `report-uri` delivery is document-initiated (Sec-Fetch-Site: same-origin),
        # but Reporting-API (`report-to`) delivery is made OUT OF BAND by the user agent's reporting
        # agent — no Sec-Fetch-* headers, possibly `Origin: null` — so assert_same_origin's Origin
        # fallback would 403 every modern report and silently blind the 3.7.5 canary. The property that
        # actually matters here is preserved: a report a FOREIGN site's CSP aimed at this endpoint
        # (log amplification) is refused. The residual exposure of the header-less path is bounded by
        # construction — the sink is unauthenticated, non-state-changing and observation-only: it
        # parses defensively, never echoes or acts on the body, logs one bounded PHI-free summary and
        # 204s, under the engine's 1 MiB request-body cap.
        assert_not_cross_site(request)
        # Browser-delivered CSP violation report (ASVS 3.7.5). UNAUTHENTICATED and non-mutating: a
        # browser attaches no session credential to a report POST, and this only observes. The body is
        # attacker-influenceable DATA (never instructions) — parse it defensively, log a BOUNDED,
        # PHI-free summary at WARNING (the /ui surface carries no message bodies in its URLs), and 204.
        # Never echo or act on the report. Both the legacy report-uri body and the modern report-to
        # ARRAY (the wired Reporting-Endpoints header) are normalized by ``_csp_report_bodies``.
        client = request.client.host if request.client else "<unknown>"
        raw = await request.body()
        if not raw:
            _log.warning("CSP violation report from %s: %s", client, "empty")
            return Response(status_code=204)
        try:
            doc = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            _log.warning("CSP violation report from %s: %s", client, "malformed-json")
            return Response(status_code=204)
        bodies = _csp_report_bodies(doc)
        if bodies is None:
            _log.warning("CSP violation report from %s: %s", client, "non-object")
            return Response(status_code=204)
        # Partition the BATCH, never classify it by one entry. The canary fires once per page load on
        # every conforming browser and the Reporting API batches per endpoint, so a real violation
        # raised on the same page load arrives in the same POST alongside the canary's report. Only
        # the canary's own entries are dropped to DEBUG (so it never floods the operational log); a
        # batch containing ANY other blocked URL — including "inline", the shape a real XSS attempt
        # produces — still WARNS, and the warning summarises the REAL entries, not the canary.
        origin = _request_origin(request)
        real = [b for b in bodies if not _is_expected_csp_probe_report(b, origin)]
        canary_count = len(bodies) - len(real)
        if canary_count:
            _log.debug("CSP enforcement canary blocked as designed (%d report(s))", canary_count)
        if real or not bodies:
            # Bounded on BOTH axes — per-field (256 chars, in the summariser), per-batch (the first
            # few entries) and overall (1024 chars) — so a hostile flood cannot inflate the log.
            shown = " | ".join(_csp_report_summary(b) for b in real[:_CSP_REPORT_SUMMARY_MAX])
            if len(real) > _CSP_REPORT_SUMMARY_MAX:
                shown += f" (+{len(real) - _CSP_REPORT_SUMMARY_MAX} more)"
            _log.warning("CSP violation report from %s: %s", client, (shown or "empty")[:1024])
        return Response(status_code=204)
