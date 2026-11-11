# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Inbound HTTP/1.1 listen source — a connector-owned SOAP/REST web-service receiver (ADR 0023).

A partner ``POST``s a body (JSON / XML / text / HL7-over-HTTP) and the listener decodes it, hands it
to the pipeline's receipt handler (:mod:`~messagefoundry.transports.receipt`) much as
:class:`~messagefoundry.transports.mllp.MLLPSource` hands a de-framed MLLP message, and returns a
**``202 Accepted`` respond-with-receipt** the instant the raw body is durably committed to the
ingress stage — mirroring MLLP's AA-on-receipt (ACK-on-receipt, ADR 0001). A post-ingress
routing/transform/delivery failure happens *after* the ``202`` and is **not** reflected in the HTTP
status — it surfaces only as the message's ``ERROR``/dead-letter disposition + the AlertSink, exactly
as a post-ACK MLLP failure does. A body the pipeline handler refuses at ingress (recorded ``ERROR``,
no ingress row) is never answered ``202``: a temporary refusal is answered ``503`` with
``Retry-After``, an over-size one ``413``, a permanent one ``422``, and a configuration one ``503``
with no ``Retry-After``, each naming the ``ERROR`` row as ``refused_message_id`` (ADR 0154
amendments 2026-09-26, 2026-10-30 and 2026-11-04). A configuration refusal is one the inbound's own
configuration caused, at least an unusable codec name: it clears only once an operator fixes the
configuration (BACKLOG #2431, #5102).

**Why this lives in ``transports/`` and not ``api/``.** The one-way dependency rule (CLAUDE.md §2/§4)
forbids ``transports/`` from importing ``api/``. The engine's FastAPI app stays the admin/RBAC surface;
message intake is a registry connector that owns its own bound ``asyncio`` socket. So this is a
**stdlib-only** HTTP/1.1 request reader over ``asyncio.start_server``, or, for TLS on a loop that
is not a stdlib loop class, over the MLLP listener's own accept loop (BACKLOG #2479) — **no new
web-framework dependency** (FastAPI/uvicorn are an ``api/`` concern).

It is a faithful ``MLLPSource`` sibling: it inherits the per-connection IP allowlist, per-connection
inbound TLS, the runner's exposed-gate (``check_http_tls_exposure``), ADR 0031 fault isolation, and the
ADR 0021 ``connection_event`` log (**on by default** — ``[diagnostics].connection_events`` is ``True``
and the per-connection flag inherits it; see ``docs/PHI.md`` §7). The DoS guards have HTTP analogs: ``max_connections``
(connection-flood), ``receive_timeout`` (slow-loris — bounds the time to read the request line +
headers + body), and ``max_body_bytes`` (the ``MLLPDecoder`` frame cap's HTTP twin — a
``Content-Length`` / read ceiling).

**Two response modes.** The default is the cheap, correct ``202``-respond-with-receipt path (ADR 0023
D3). An inbound naming ``reply_from`` instead **blocks** the HTTP turn until the named outbound's reply
has been captured *and committed*, then returns it as the body (ADR 0154 increment B, via the ADR 0013
capture seam) — see :func:`~messagefoundry.config.wiring.Http` for the settings and their check-time
refusals. ``GET``/``HEAD`` are answered with a static, non-PHI health response **without** an ingress
row; any other method is ``405``.
"""

from __future__ import annotations

import asyncio
import bisect
import contextlib
import functools
import ipaddress
import json
import logging
import re
import socket
import ssl
import time
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any, ClassVar, assert_never, cast

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.settings import (
    _IPV4_MAPPED_BASE,
    _classify_proxy_entries,
    _ipv4_meaning,
    _not_a_host_address,
    _parse_trusted_proxy,
)
from messagefoundry.credential import (
    OTHERNAMES_INTACT_KEY,
    VERIFIED_ISSUER_KEY,
    client_cert_principal_under_issuer,
    constant_time_match_any,
)
from messagefoundry.proactor_accept import guard_accepts
from messagefoundry.redaction import safe_exc
from messagefoundry.tls_handshake_failures import HUNG_UP, HandshakeFailures, handshake_cause
from messagefoundry.transports.admission import ListenerAdmission
from messagefoundry.transports.base import (
    INTAKE_AUDIT_ACTIONS,
    InboundHandler,
    InboundReply,
    ReplyOutcome,
    SourceConnector,
    port_setting,
    positive_cap,
    positive_seconds,
    register_source,
    wait_for_intake,
)
from messagefoundry.transports.mllp import (
    _TLS_HANDSHAKE_TIMEOUT,
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_RECEIVE_TIMEOUT,
    _AcceptedPeer,
    _AcceptingServer,
    _bind_tcp,
    _HandshakeProtocol,
    _lost_its_transport,
    _MessagePacer,
    _mllp_ssl_context,
    _pacing_settings,
    _peer_host,
    _set_tcp_nodelay,
)

# The MLLP listener's own predicate, re-exported so a test can force either path on this module
# alone (BACKLOG #2479): this listener runs the same accept loop where it returns False.
from messagefoundry.transports.mllp import _upgrades_tls_itself as _upgrades_tls_itself
from messagefoundry.transports.receipt import ReceiptHandler, RefusalKind, require_receipt

if TYPE_CHECKING:
    from messagefoundry.pki import IssuerIndex

__all__ = [
    "DEFAULT_MAX_BODY_BYTES",
    "DEFAULT_MAX_HANDSHAKES_PER_HOST",
    "DEFAULT_MAX_HEADER_BYTES",
    "HttpRequest",
    "HttpRequestError",
    "HttpSource",
    "reply_seconds",
    "trusted_proxy_networks",
]

logger = logging.getLogger(__name__)


# Resource caps (DoS guards), HTTP analogs of the MLLP frame/connection/idle caps. All overridable per
# connection via Http() settings; None/0 (in any spelling) disables a cap explicitly where noted.
DEFAULT_MAX_BODY_BYTES = (
    16 * 1024 * 1024
)  # 16 MiB — matches the MLLP frame cap + the engine ceiling
DEFAULT_MAX_HEADER_BYTES = (
    64 * 1024
)  # cap the request line + headers (a header-flood / slow-loris guard)
#: The most sockets one peer address may hold a ``max_connections`` slot with while still in
#: their TLS handshake (vault BACKLOG #4888). A TLS socket holds one from its admission, before its
#: handshake, on every event loop (BACKLOG #2479). 32 is an eighth of
#: :data:`DEFAULT_MAX_CONNECTIONS`, the ratio the other listeners' per-host cap ships at, so at the
#: default ``max_connections`` a stalling address could hold at most an eighth of the listener. The
#: budget does not scale with ``max_connections``: at 32 slots or fewer, ``max_connections`` refuses
#: first and one stalling address could hold every slot. ``docs/DEPLOYMENT.md``, *Per-address
#: listener caps behind the VIP*, holds the rationale and the L4 load-balancer counter-case.
DEFAULT_MAX_HANDSHAKES_PER_HOST = 32
_HEADER_CAP_OFF_HINT = (
    "this cap cannot be switched off; leave it unset or None for the 64 KiB default"
)

# On stop()/reload, established clients are closed and their handlers given this long to finish an
# in-flight commit before the connection tasks are cancelled (mirrors MLLPSource; bounds shutdown).
_CLIENT_SHUTDOWN_GRACE = 5.0


class HttpRequestError(Exception):
    """A request could not be parsed / exceeded a cap **before** an ingress row was written.

    Carries the HTTP ``status`` to return synchronously (the HTTP twin of MLLP's synchronous AR/AE
    NAK) and a connection-event ``kind`` (ADR 0021 §7, metadata-only) for the pre-ingress failure.
    """

    def __init__(
        self, status: int, reason: str, *, kind: str, headers: Mapping[str, str] | None = None
    ) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.kind = kind
        #: The client address a listed proxy forwarded, which the failed-attempt budget keyed this
        #: refusal on, or ``None`` where it keyed on the socket peer (BACKLOG #5525). Set by
        #: ``HttpSource._authorize_head``, and read only to record it beside the socket peer.
        self.forwarded_for: str | None = None
        #: Extra response headers this refusal owes the peer — ``WWW-Authenticate`` on a ``401``,
        #: ``Retry-After`` on a ``429`` (ADR 0154 D6). Additive so the intake-auth refusals ride the
        #: shipped ``HttpRequestError`` arm in ``_serve_one`` rather than growing a parallel one.
        self.headers = dict(headers) if headers else None


class HttpRequest:
    """One parsed inbound HTTP request — method/path/headers + the body bytes.

    Treated as **untrusted data** (CLAUDE.md §8): the method/path/headers are surfaced as routing
    metadata (ADR 0004 §4), never executed; the body is handed verbatim to the pipeline handler.
    """

    __slots__ = ("method", "target", "headers", "body", "repeated", "forwarded_header")

    def __init__(
        self,
        method: str,
        target: str,
        headers: dict[str, str],
        body: bytes,
        repeated: frozenset[str],
        forwarded_header: str = "",
    ) -> None:
        self.method = method
        self.target = target
        self.headers = headers
        self.body = body
        #: Names of the headers that appeared more than once, lower-cased with ``_`` read as ``-``
        #: (so ``x_api_key`` and ``x-api-key`` count as one name, as a folding front end reads them).
        #: ``headers`` keeps only the LAST value of each, so a caller that reads a security-relevant
        #: header checks here first (BACKLOG #2051).
        self.repeated = repeated
        #: Every ``X-Forwarded-For`` line joined with ``,`` in the order received, as uvicorn joins
        #: them. ``headers`` keeps only the last line, and the walk in
        #: ``HttpSource._forwarded_client`` must cross line boundaries (BACKLOG #5525).
        self.forwarded_header = forwarded_header


def _status_line(status: int) -> str:
    reason = {
        200: "OK",
        202: "Accepted",
        204: "No Content",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        405: "Method Not Allowed",
        408: "Request Timeout",
        411: "Length Required",
        413: "Payload Too Large",
        422: "Unprocessable Content",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
    }.get(status, "")
    # The fallback is the empty reason-phrase, not "OK". RFC 9110 §15 makes the phrase advisory and
    # allows it to be empty (the SP before it is still required), so an unmapped code goes out as
    # `HTTP/1.1 599 ` — uninformative but true. Defaulting to "OK" is what serialised the
    # at-capacity refusal as `HTTP/1.1 503 OK`: a response whose line claimed success while its code
    # reported failure. Completing the table fixes the code we emit today; the honest fallback fixes
    # whichever one we forget to add next.
    return f"HTTP/1.1 {status} {reason}"


#: A header field-name: RFC 9110 ``token`` — one or more ``tchar``. Notably excludes ``:`` and space.
_HEADER_NAME_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
#: A header field-value: printable US-ASCII, no leading or trailing space, and **no control
#: characters at all** — which is what excludes CR and LF, the header-injection primitive.
_HEADER_VALUE_RE = re.compile(r"[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?")

#: ``Content-Length = 1*DIGIT`` (RFC 9112 section 6.2), used INSTEAD of ``int()`` on the intake
#: path. ``int()`` accepts a leading sign and PEP 515 underscores, so ``1_0`` framed ten bytes and
#: ``+3`` framed three -- both measured against the shipped parser (BACKLOG #1125).
_CONTENT_LENGTH_RE = re.compile(r"[0-9]+")

#: The two headers that frame a request body. A name that becomes one of these once ``_`` is read
#: as ``-`` is refused (BACKLOG #1913): ``Transfer_Encoding`` is a valid token, so it slipped past
#: both framing guards here, while a front end that folds underscores into hyphens reads it as real.
_FRAMING_HEADERS = frozenset({"content-length", "transfer-encoding"})

#: The health-probe methods: answered with a static 200 and no ingress row (ADR 0023 D2).
_HEALTH_PROBE_METHODS = frozenset({"GET", "HEAD"})

#: Methods this listener ingests a body for. Each must declare a ``Content-Length``; with none the
#: request is refused 411 in the head parse rather than read to EOF (BACKLOG #1125). Every OTHER
#: method, the health probes included, may declare only ``Content-Length: 0``: it declares no body
#: and desyncs nothing, and it is the shape a health checker actually sends. A non-zero length is
#: refused, because those are the declared bytes this listener would never read.
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})

#: The ``error`` text of every answer to a body the receipt handler refused AFTER recording it with
#: status ERROR. ``RegistryRunner._handle_inbound_http`` holds the guards that do this. The receipt
#: path and the sync-reply path both answer it, so a caller is never told a refused body was accepted
#: (owner ruling 2026-09-26, the ADR 0154 amendment of that date, BACKLOG #1960).
_NOT_ACCEPTED = "message was not accepted"

#: The ``Retry-After`` seconds on the ``503`` answering a TEMPORARY ingress refusal, as ADR 0154's
#: 2026-10-30 amendment states it (BACKLOG #2105). The ``503`` with ``Retry-After`` is the owner
#: ruling of 2026-09-30. The sync path's shutting-down ``503`` in ``_reply_to_wire`` is a different
#: answer and sets its own.
TEMPORARY_REFUSAL_RETRY_AFTER_SECONDS = 5


def _refusal_status(kind: RefusalKind) -> tuple[int, dict[str, str] | None]:
    """The status a refusal of ``kind`` is answered with, and its extra headers (ADR 0154
    amendments 2026-10-30 and 2026-11-04). Only a temporary refusal invites a re-send soon, with
    ``Retry-After``; a configuration refusal is the same ``503`` without it, since it clears only
    when an operator acts (BACKLOG #5102). An over-size body answers the same ``413`` as one over
    ``max_body_bytes``. One ``match`` with ``assert_never`` decides both, so mypy refuses a new kind
    left unmapped rather than a ``KeyError`` answering ``500`` after the ``ERROR`` row was written,
    and no kind gets its header from a second test."""
    match kind:
        case RefusalKind.TEMPORARY:
            return 503, {"Retry-After": str(TEMPORARY_REFUSAL_RETRY_AFTER_SECONDS)}
        case RefusalKind.CONFIGURATION:
            return 503, None
        case RefusalKind.OVERSIZE:
            return 413, None
        case RefusalKind.PERMANENT:
            return 422, None
        case _:
            assert_never(kind)


#: A ``Content-Length`` with more significant digits than this is refused. It is far past any body
#: cap, and ``int()`` raises past 4300 digits (CPython's ``sys.int_info.default_max_str_digits``),
#: counting leading zeros, which escaped as a 500. So the head parse strips the zeros, checks this
#: cap, and stores the normalised digits; no ``int()`` ever sees the raw wire text.
_MAX_CONTENT_LENGTH_DIGITS = 18

#: A request-target: visible US-ASCII only (RFC 9112 section 3.2, RFC 3986). No space, HTAB, VT,
#: FF or other control character, which some recipients treat as request-line separators.
_REQUEST_TARGET_RE = re.compile(r"[\x21-\x7e]+")

#: A control character in a header field-value (RFC 9110 section 5.5 allows VCHAR, obs-text, SP and
#: HTAB). CR and LF are already refused with the head; this catches the rest, NUL included.
_FIELD_VALUE_CTL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")

#: ``HTTP-version = "HTTP/" DIGIT "." DIGIT`` (RFC 9112 section 2.3), and the major version must be 1.
#: A ``startswith("HTTP/")`` test accepted ``HTTP/1.1x``; a fronting proxy that parses the version
#: strictly and an origin that does not is one of the shapes a desync is built from. HTTP/0.9 has no
#: header block and HTTP/2 is not a text protocol, so neither is parsed with HTTP/1.1 framing.
_HTTP_VERSION_RE = re.compile(r"HTTP/1\.[0-9]")


def _validated_header(name: str, value: str) -> str:
    """One serialized ``Name: value`` line, or raise if either side could break the header block.

    **Rejects rather than sanitises** (ADR 0154 D5 / AC-9). The existing
    ``_strip_header_control_chars`` helper cannot serve here: it contains no regex and it *removes*
    offending characters, which would silently reshape a partner's ``Content-Type`` into something
    they never sent instead of failing the turn.

    Uses ``re.fullmatch`` deliberately, never a ``$``-anchored ``re.match``: in Python ``$`` also
    matches immediately before a trailing newline, so ``match(r"...$", "text/plain\\r\\n...")`` would
    accept the very injection this exists to stop.

    The offending **value is never placed in the exception** — it is partner-controlled and, on the
    capture path, potentially PHI. The header name is enough to diagnose the configuration.
    """
    if not _HEADER_NAME_RE.fullmatch(name):
        raise ValueError(f"invalid HTTP header name: {name!r}")
    if not _HEADER_VALUE_RE.fullmatch(value):
        raise ValueError(
            f"invalid HTTP header value for {name!r} (control characters or whitespace)"
        )
    return f"{name}: {value}"


#: The browser-safety baseline every response from this listener carries (ASVS 3.4.3 / 3.4.4 / 3.4.6).
#:
#: **This is a deliberate SECOND copy of ``api/header_floor.BASELINE_SECURITY_HEADERS`` and the
#: floor's CSP beside it (``FLOOR_CSP``: frame-ancestors and base-uri), and the duplication is forced by the dependency rule this
#: module's own docstring states: ``transports/`` must not import ``api/``** (and ``header_floor``
#: imports Starlette, which has no business in a connector). A copy that can drift silently is the
#: failure ``header_floor`` exists to end, so it does not drift silently here either:
#: ``tests/test_inbound_http_source.py`` imports both and asserts they are equal, which is the single
#: place a divergence reds. Do not "fix" this by importing across the boundary.
#:
#: ``Strict-Transport-Security`` is deliberately ABSENT. It would have to be gated on THIS
#: connection's own TLS context (``Http(tls_certfile=...)``) rather than on the API's, and on the same
#: RFC 6797 notability tests the API applies -- that is a separate piece of work, named rather than
#: half-built, because a wrongly-gated HSTS is worse than none.
_BASELINE_RESPONSE_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    # base-uri beside frame-ancestors, as the API floor sends it (ASVS 3.4.3, BACKLOG #2341). One
    # field, decided by NAME: no caller of build_response supplies a CSP today (handlers cannot set
    # response headers here), and one that did would own the whole policy, as the test pins.
    ("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'"),
)


def build_response(
    status: int,
    body: str = "",
    *,
    content_type: str = "application/json",
    extra_headers: Mapping[str, str] | None = None,
) -> bytes:
    """Serialize a minimal HTTP/1.1 response. ``Connection: close`` — the first slice is
    one-request-per-connection (no keep-alive), which sidesteps a pipelining/half-close attack surface
    and matches the fire-and-forget webhook shape. No PHI is ever placed in a response body here.

    ``extra_headers`` carries the auth challenges intake authentication owes a peer —
    ``WWW-Authenticate`` on a ``401``, ``Retry-After`` on a ``429``.

    **Every response also carries :data:`_BASELINE_RESPONSE_HEADERS`** (ASVS 3.4.4 / 3.4.6). This
    function is the chokepoint all twelve call sites feed, so the baseline is a property of the
    serializer rather than a list of remembered call sites. It matters most on the ADR 0154 sync-reply
    path below, which echoes a DOWNSTREAM PARTNER'S ``Content-Type`` verbatim beside partner-supplied
    bytes: without ``nosniff`` and a framing decision that response can serve a partner-derived
    ``text/html`` document over this listener's own TLS. ``extra_headers`` still wins on a name
    collision.

    **Every header name and value, including ``content_type``, is validated here rather than at the
    call site.** This function joins the header block with ``\\r\\n``, so it *is* the chokepoint: a
    value carrying CR or LF is a header-injection primitive, and validating in the callers would mean
    each future consumer has to remember. Today every caller passes a literal, so this guards against
    a future one — notably the captured-reply path, which echoes a partner's ``Content-Type``.

    **A ``204`` carries no entity headers.** RFC 9110 §15.3.5 forbids a body on a ``204``, and
    ``Content-Length: 0`` beside it is at best noise and at worst a parser tripwire — some clients
    treat an entity header on a bodyless status as a framing error. That matters here rather than
    academically: ``reply_on_empty="204"`` is the default answer for a partner reply that is
    deliberately empty, so this is ordinary traffic, not an edge case."""
    payload = body.encode("utf-8")
    headers = [_status_line(status)]
    if status != 204:
        headers.append(_validated_header("Content-Type", content_type))
        headers.append(f"Content-Length: {len(payload)}")
    supplied = {name.casefold() for name in (extra_headers or {})}
    # setdefault semantics, not an unconditional write: a caller that has made its own decision about
    # one of these names keeps it, and no name is ever emitted twice. Placed BEFORE extra_headers so
    # the reading order matches the precedence.
    headers.extend(
        _validated_header(name, value)
        for name, value in _BASELINE_RESPONSE_HEADERS
        if name.casefold() not in supplied
    )
    headers.extend(_validated_header(name, value) for name, value in (extra_headers or {}).items())
    headers.extend(("Connection: close", "", ""))
    return "\r\n".join(headers).encode("ascii") + payload


async def _read_head(
    reader: asyncio.StreamReader,
    *,
    max_header_bytes: int,
) -> HttpRequest:
    """Read + parse the request line and headers only, applying the header cap.

    Returns an :class:`HttpRequest` whose ``body`` is still empty; the caller decides when — and
    whether — to read it, via :func:`_read_body`.

    **The split is a security boundary, not tidying** (ADR 0154 D6). It is what lets intake
    authentication examine a request's credentials *before* its body is buffered. Authenticating
    after a combined read would let an anonymous peer command up to
    ``max_connections × max_body_bytes`` of resident heap before a single credential byte was
    examined. The connection cap cannot shed that load either,
    because it is consulted earlier still, in ``_on_client``. Keep any new pre-body refusal here.

    Raises :class:`HttpRequestError` (carrying the status + connection-event kind) on an unbounded
    header read, a malformed request line, ambiguous framing, or a missing or repeated ``Host``,
    so the caller can answer synchronously **before** any ingress row is written."""
    # Request line + headers, bounded by max_header_bytes (so a peer can't stream headers forever).
    # Each refusal is raised OUTSIDE its handler: IncompleteReadError.partial holds every header byte
    # read so far, credentials included, and a raise inside the handler would chain it (#2085).
    head = b""
    refused: HttpRequestError | None = None
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError:
        refused = HttpRequestError(400, "incomplete request head", kind="framing_error")
    except asyncio.LimitOverrunError:
        # StreamReader's own buffer limit tripped before the terminator — treat as an oversize head.
        refused = HttpRequestError(413, "request head exceeds cap", kind="frame_oversize")
    if refused is not None:
        raise refused
    if len(head) > max_header_bytes:
        raise HttpRequestError(413, "request head exceeds cap", kind="frame_oversize")

    # HTTP/1.1 header octets are latin-1 (RFC 7230), which maps every byte, so this cannot fail.
    text = head.decode("iso-8859-1")

    # A BARE LF IS REFUSED BEFORE THE HEAD IS SPLIT, and this one is not pedantry (BACKLOG #1125).
    # RFC 9112 section 2.2 makes CRLF the only line terminator. Splitting on "\r\n" alone leaves a
    # bare LF INSIDE a line, which measurably fused two headers into one: `Host: t\nContent-Length: 3`
    # parsed to a single `host` field and the Content-Length VANISHED from the dict, so both framing
    # guards below inspected a request whose framing header they could no longer see. A bare LF in
    # the request line was worse -- the header dict came out EMPTY while the body was still read.
    # A fronting proxy that accepts bare LF as a terminator and an origin that does not is the
    # textbook desync pair, so this is refused rather than normalised.
    #
    # A BARE CR is the same primitive from the other side. RFC 9112 section 2.2 lets a recipient
    # treat it as a line break, so `Host: h\rContent-Length: 3` is a Host header here and a
    # Content-Length to a proxy that splits on CR. That shape measurably reached the POST path with
    # the Content-Length hidden inside the Host value.
    bare = text.replace("\r\n", "")
    if "\n" in bare:
        raise HttpRequestError(400, "bare LF in request head", kind="framing_error")
    if "\r" in bare:
        raise HttpRequestError(400, "bare CR in request head", kind="framing_error")

    try:
        lines = text.split("\r\n")
        request_line = lines[0]
        method, target, version = request_line.split(" ", 2)
    except ValueError as exc:
        raise HttpRequestError(400, "malformed request line", kind="framing_error") from exc
    # `method = token` (RFC 9110 section 9.1). Checked here because the method now selects the
    # framing rule below, so a method this parser and a proxy disagree on is a framing decision.
    if (
        not _HEADER_NAME_RE.fullmatch(method)
        or not _REQUEST_TARGET_RE.fullmatch(target)
        or not _HTTP_VERSION_RE.fullmatch(version)
    ):
        raise HttpRequestError(400, "malformed request line", kind="framing_error")

    headers: dict[str, str] = {}
    header_counts: dict[str, int] = {}
    # Counted with `_` folded into `-`, because some front ends fold the two (BACKLOG #1913), so a
    # repeat hidden behind an underscore spelling is still a repeat (BACKLOG #2051).
    folded_counts: dict[str, int] = {}
    forwarded_lines: list[str] = []
    for line in lines[1:]:
        if not line:
            continue
        # A LINE THAT STARTS WITH SPACE OR TAB IS AN obs-fold CONTINUATION (RFC 9112 section 5.2),
        # and a server must refuse it or unfold it. Before this check `.strip()` read
        # ` Content-Length: 3` as a real framing header, while a proxy that unfolds reads it as
        # more of the previous header's value. Refused, like every other shape the two could split on.
        if line[0] in " \t":
            raise HttpRequestError(400, "obsolete line folding in header", kind="framing_error")
        name, sep, value = line.partition(":")
        if not sep:
            raise HttpRequestError(400, "malformed header line", kind="framing_error")
        # WHITESPACE BEFORE THE COLON IS A MUST-REJECT (RFC 9112 section 5.1), not something to
        # strip. `.strip()` normalised `Content-Length : 3` into a valid framing header, which is
        # precisely the shape a strict proxy drops and a lenient origin honours.
        if name != name.rstrip():
            raise HttpRequestError(400, "whitespace before header colon", kind="framing_error")
        # `field-name = token`. Anything else is a name a proxy may read differently.
        if not _HEADER_NAME_RE.fullmatch(name):
            raise HttpRequestError(400, "malformed header line", kind="framing_error")
        # Only OWS (SP and HTAB) is trimmed. `str.strip()` also removed VT, FF, NBSP and NEL, so
        # `Content-Length: 3\x0b` framed three bytes here while a strict proxy refused the header.
        if _FIELD_VALUE_CTL_RE.search(value):
            raise HttpRequestError(400, "control character in header value", kind="framing_error")
        key = name.lower()
        folded = key.replace("_", "-")
        if folded != key and folded in _FRAMING_HEADERS:
            raise HttpRequestError(400, "underscore in a framing header name", kind="framing_error")
        header_counts[key] = header_counts.get(key, 0) + 1
        folded_counts[folded] = folded_counts.get(folded, 0) + 1
        headers[key] = value.strip(" \t")
        if key == _FORWARDED_FOR:
            forwarded_lines.append(headers[key])

    # Reject AMBIGUOUS framing before any Content-Length is trusted — the HTTP request-smuggling
    # defense (RFC 7230 §3.3.3). A duplicate Content-Length / Transfer-Encoding, or the two present
    # together, is exactly how a request is desynced past a fronting proxy (a dict collapses the
    # duplicate silently, so it must be caught here). A conformant client sends neither. Checked for
    # every method, before the GET/HEAD no-body short-circuit — smuggled framing on a GET still counts.
    if header_counts.get("content-length", 0) > 1 or header_counts.get("transfer-encoding", 0) > 1:
        raise HttpRequestError(400, "duplicate framing header", kind="framing_error")
    if "content-length" in headers and "transfer-encoding" in headers:
        raise HttpRequestError(
            400, "ambiguous framing: Content-Length with Transfer-Encoding", kind="framing_error"
        )

    # The method is NOT case-folded: it is a case-sensitive token (RFC 9110 section 9.1), and it
    # picks the framing rule below. Folding `post` to POST would apply a rule a proxy does not.

    # FRAMING IS DECIDED HERE, FOR EVERY METHOD, BEFORE ANY METHOD DISPATCH (BACKLOG #1125, ASVS
    # 4.2.1). RFC 9112 makes framing a property of the MESSAGE, not of the method, and the earlier
    # arrangement -- a GET/HEAD short-circuit in `_read_body` that ran BEFORE the framing refusal --
    # accepted a GET carrying `Transfer-Encoding: chunked` or a `Content-Length` with an empty body
    # and its declared bytes left unread on the socket.
    #
    # **Refuse, never consume.** Measured before this change: a GET declaring 16 MiB and sending
    # none was answered 200 in 0.002s, while the POST path held the socket for the full 3s
    # `receive_timeout`. Making a bodyless method READ its declared body would hand an
    # unauthenticated peer a slow-loris hold on the cheapest path; refusing answers faster than
    # either.
    #
    # `Transfer-Encoding` is refused by PRESENCE, not by matching `chunked`. This listener decodes
    # no transfer coding, and an exact-equality test measurably missed `gzip, chunked`, `chunked,`
    # and `identity`, all of which reached the POST path and were ingested as clinical payload.
    # This is a deliberate departure from RFC 9112, not conformance: section 7 makes parsing
    # chunked a MUST, and section 6.1 says an unknown coding SHOULD get 501. Every coding gets the
    # same 400 here, so one framing refusal covers them all (BACKLOG #1125, #1913).
    if "transfer-encoding" in headers:
        raise HttpRequestError(
            400, "transfer-encoding is not supported; use Content-Length", kind="framing_error"
        )

    cl_raw = headers.get("content-length")
    if cl_raw is not None:
        # `1*DIGIT` per RFC 9112, NOT `int()`. `int()` accepts a leading plus and PEP 515
        # underscores, so `Content-Length: 1_0` framed TEN bytes and `+3` framed three -- measured.
        if not _CONTENT_LENGTH_RE.fullmatch(cl_raw):
            raise HttpRequestError(400, "invalid Content-Length", kind="framing_error")
        digits = cl_raw.lstrip("0") or "0"
        if len(digits) > _MAX_CONTENT_LENGTH_DIGITS:
            raise HttpRequestError(400, "invalid Content-Length", kind="framing_error")
        headers["content-length"] = digits
        # CARVE-OUT, and it is the one shape the tree actually exercises: `Content-Length: 0` on a
        # method this listener reads no body for declares no body, so it desyncs nothing and a
        # health checker that sends it stays green. A NON-ZERO length there is refused -- those are
        # the declared bytes that would be left on the wire, or buffered only to answer 405.
        if method not in _BODY_METHODS and digits != "0":
            raise HttpRequestError(400, "request must not declare a body", kind="framing_error")
    elif method in _BODY_METHODS:
        # A BODY METHOD WITH NO FRAMING IS REFUSED, NOT READ TO EOF. RFC 9112 section 6.3 says such
        # a request has a ZERO-length body, so a proxy forwards the head and treats any bytes after
        # it as the next request, while the old read-to-EOF path ingested those same bytes as this
        # request's clinical payload. 411 Length Required is the RFC 9110 status for a server that
        # refuses a request with no Content-Length.
        raise HttpRequestError(411, "Content-Length is required", kind="framing_error")

    # HOST MUST APPEAR EXACTLY ONCE ON HTTP/1.1, AND NEVER TWICE ON ANY VERSION (RFC 9112 section
    # 3.2, BACKLOG #1972). A server MUST answer 400 to either shape. This listener reads no Host
    # value, so the refusal is RFC conformance first. It also helps a fronting proxy that does read
    # Host. The dict above keeps only the last of two Host lines, while such a proxy may act on the
    # first. This check runs after the framing refusals, so a smuggling probe keeps its own reason.
    # HTTP/1.0 predates the field, so a 1.0 request with no Host still parses. Every other 1.x minor
    # is read as 1.1 (RFC 9110 section 2.5). An EMPTY value counts as present, because RFC 9112 has
    # a client send it when the target URI has no authority. The value's syntax is NOT checked here,
    # and the refusal reason never carries the value.
    host_count = header_counts.get("host", 0)
    if host_count > 1:
        raise HttpRequestError(400, "duplicate Host header", kind="framing_error")
    if host_count == 0 and version != "HTTP/1.0":
        raise HttpRequestError(400, "missing Host header", kind="framing_error")

    repeated = frozenset(name for name, count in folded_counts.items() if count > 1)
    return HttpRequest(method, target, headers, b"", repeated, ",".join(forwarded_lines))


async def _read_body(
    reader: asyncio.StreamReader,
    head: HttpRequest,
    *,
    max_body_bytes: int | None,
) -> bytes:
    """Read the body belonging to an already-parsed ``head``, applying the body cap.

    Split out of :func:`_read_request` so authentication can run between the two halves (see
    :func:`_read_head`).

    **This function no longer decides framing, and the ordering warning that used to live here is
    gone because the thing it warned about was done deliberately** (BACKLOG #1125, ASVS 4.2.1). It
    said the GET/HEAD short-circuit running before the chunked refusal was load-bearing, and that
    hoisting the refusal "would read as hardening and would in fact be a silent behaviour change".
    The change was not silent: it went to adversarial review, and the authoring commit was read
    (``f2ef0ea92``, the ADR 0154 intake-auth increment) and names no ruling and no incident -- it
    was change-control caution to stop that refactor altering behaviour by accident, and it worked.

    Framing is now settled in :func:`_read_head` for EVERY method before dispatch, so by the time
    this runs a ``Transfer-Encoding`` has already been refused and a ``Content-Length`` is already
    known to be at most 18 normalised digits, to be present on a body method, and to be absent or
    zero on every other method. What remains here is the read itself."""
    # Only body methods read one. Any other method reaching this point has already been proven to
    # declare no body, so this discards nothing that was ever on the wire.
    if head.method not in _BODY_METHODS:
        return b""

    cl_raw = head.headers.get("content-length")
    if cl_raw is None:
        # The head parse refuses this; kept so a head built any other way can never fall through
        # to an empty body committed as a message.
        raise HttpRequestError(411, "Content-Length is required", kind="framing_error")
    content_length = int(cl_raw)  # at most 18 digits, normalised by the head parse
    if max_body_bytes is not None and content_length > max_body_bytes:
        # Refuse on the DECLARED size before reading a single body byte (don't buffer to find out).
        raise HttpRequestError(413, "body exceeds cap", kind="frame_oversize")
    return await _read_exactly(reader, content_length)


async def _read_request(
    reader: asyncio.StreamReader,
    *,
    max_header_bytes: int,
    max_body_bytes: int | None,
) -> HttpRequest:
    """Read + parse one whole HTTP/1.1 request — :func:`_read_head`, then :func:`_read_body`.

    Retained as the composing wrapper after the ADR 0154 D6 split rather than replaced by it. It is
    the shape the shipped 202-only path and its tests already use, and it keeps "read the whole
    request" expressible in one call for any caller with no credential to check between the halves."""
    head = await _read_head(reader, max_header_bytes=max_header_bytes)
    head.body = await _read_body(reader, head, max_body_bytes=max_body_bytes)
    return head


async def _read_exactly(reader: asyncio.StreamReader, n: int) -> bytes:
    """Read exactly ``n`` declared Content-Length body bytes, or refuse.

    A peer that closes before sending all of it has broken its own declared framing — the same
    class of defect :func:`_read_head` already refuses via :class:`HttpRequestError`, just on the
    body side. Silently returning the short ``exc.partial`` bytes would let a truncated body flow
    on to become an ingress row and a 202, understating what the sender actually declared."""
    if n == 0:
        return b""
    # Refused outside the handler: IncompleteReadError.partial holds the body read so far (#2085).
    with contextlib.suppress(asyncio.IncompleteReadError):
        return await reader.readexactly(n)
    raise HttpRequestError(400, "incomplete request body", kind="framing_error")


def _header_cap(value: Any) -> int:
    """Read ``max_header_bytes``, the one cap on this listener that cannot be switched off.

    Unset, ``None`` and ``""`` (an env var that is set but empty) take the 64 KiB default. Anything
    else must be a positive number of bytes, and zero is refused in every spelling (BACKLOG #1872).
    Before that, a TOML ``0`` silently became the default while a string ``"0"`` became a cap of zero
    that refused every request, because no request has a head of zero bytes: one number, two outcomes,
    one of them a total outage. Both now refuse loudly, because an operator who writes 0 means "no cap",
    and this listener does not offer one; silently substituting 64 KiB would hide that. This is the
    ``max_decompressed_members`` rule on the File source, read the same way."""
    if value is None or value == "":
        return DEFAULT_MAX_HEADER_BYTES
    cap = positive_cap(
        value,
        int,
        knob="max_header_bytes",
        transport="HTTP source",
        off_hint=_HEADER_CAP_OFF_HINT,
    )
    if cap is None:  # zero, in some spelling
        raise ValueError(
            "HTTP source max_header_bytes must be above zero "
            f"(value withheld; {_HEADER_CAP_OFF_HINT})"
        )
    return cap


def reply_seconds(s: Mapping[str, Any], key: str) -> float:
    """Read ``reply_timeout`` or ``reply_write_timeout``: seconds above zero, or 30 when unset.

    Unset, ``None`` and ``""`` take the 30-second default. Anything else is read by
    :func:`~messagefoundry.transports.base.positive_seconds`, so it must be above zero, as
    ``docs/CONNECTIONS.md`` says, because each bounds a blocked HTTP turn (BACKLOG #3432). The
    ``float(s.get(key) or 30.0)`` this replaces read ``True`` as one second, took a NaN, and let
    ``"0"`` through as a zero budget while a numeric ``0`` became the default. The runner reads
    ``reply_timeout`` for its reply resolver through this function too, from the unresolved spec
    settings; that agrees with this connector while the ``Http`` factory refuses a non-literal."""
    value = s.get(key)
    if value is None or value == "":
        return 30.0
    return positive_seconds(value, knob=key, transport="HTTP source")


#: The header a reverse proxy appends the client's address to. Only this exact spelling is read, as
#: uvicorn reads it: ``X_Forwarded_For`` is a different header to a proxy that does not fold ``_``.
_FORWARDED_FOR = "x-forwarded-for"
#: A port after an ``X-Forwarded-For`` hop, which some proxies write (``a.b.c.d:port``, ``[v6]:port``).
_HOP_PORT_RE = re.compile(r"[0-9]{1,5}")
#: The most listed hops the walk reads before it gives up and keys on the socket peer. A real proxy
#: chain is a handful of hops; the bound keeps a padded header from costing the event loop more.
_MAX_FORWARDED_HOPS = 32
#: The prefix an IPv6 budget key keeps. A host is usually handed a whole ``/64`` and may pick any
#: address in it, so keying on the full address would let it mint a fresh budget per address.
_IPV6_KEY_PREFIX = 64
#: IPv6 prefixes whose addresses carry an IPv4 client, so one ``/64`` of them may hold unrelated
#: hosts, or one IPv4 holder may hold many ``/64`` networks of them: the NAT64 well-known and
#: local-use prefixes (RFC 6052, RFC 8215), Teredo (RFC 4380), 6to4 (RFC 3056) and the deprecated
#: IPv4-compatible form. An address in one never keys on its ``/64`` (:func:`_budget_key`), and a
#: listed range in one counts its keys toward the span limit (:func:`_v6_key_count`), not its
#: ``/64`` networks.
_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL_USE = ipaddress.IPv6Network("64:ff9b:1::/48")
_SIX_TO_FOUR = ipaddress.IPv6Network("2002::/16")
_IPV4_COMPATIBLE = ipaddress.IPv6Network("::/96")
_IPV4_EMBEDDING_PREFIXES = (
    _NAT64_WELL_KNOWN,
    _NAT64_LOCAL_USE,
    ipaddress.IPv6Network("2001::/32"),
    _SIX_TO_FOUR,
    _IPV4_COMPATIBLE,
)
#: Where no client holds an address (:func:`_is_phantom`): the IETF-reserved ``::/8``, outside the
#: parts of it that are assigned, which are the IPv4-compatible ``::/96``, the IPv4-mapped
#: ``::ffff:0:0/96`` (read as IPv4 before this is asked), NAT64's well-known ``/96`` and its
#: local-use ``/48``; and, inside an embedding, IPv4 that is no host's, by the rule
#: ``config.settings._not_a_host_address`` applies (at least "this network", multicast and the
#: reserved class E block).
_IETF_RESERVED = ipaddress.IPv6Network("::/8")
#: The most budget keys the listed ranges of one family may hold together: addresses for IPv4, and
#: ``/64`` networks for IPv6, the unit an IPv6 key is. ``2**16`` is one ``/16`` of IPv4 or one
#: ``/48`` of IPv6. Every host inside a listed range is trusted as a proxy and may write any
#: ``X-Forwarded-For`` it likes, so this bounds the address space trusted that way, counted in
#: the unit a key is; an IPv6 ``/64`` may still hold many hosts. It is a size, not a
#: whole-family test, so a near-whole range such as ``2000::/3``, or ``/1`` to ``/3`` pieces
#: that leave one gap, is refused as the refused ``'*'`` is (BACKLOG #5525).
_PROXY_SPAN_LIMIT = 1 << 16

_ProxyNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_HopAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def trusted_proxy_networks(value: Any) -> tuple[_ProxyNetwork, ...]:
    """Read ``Http(trusted_proxies=...)`` into the networks the forwarded-address walk matches
    (BACKLOG #5525). Raises ``ValueError``; the ``Http`` factory and the listener both call it.

    Each entry is read by ``_parse_trusted_proxy``, the one reader of ``[api].trusted_proxies``,
    so this list refuses the same forms: ``'*'``, an entry uvicorn would read as a literal that
    never matches, and an IPv6 entry with a zone. It does NOT read ``[api].trusted_proxies`` itself:
    trusting the admin API's proxy says nothing about who fronts a partner intake socket. Entries
    that together trust a whole address family, as ``_classify_proxy_entries`` counts them (two
    ``/1`` halves included), are refused here too, since that is ``'*'`` written as networks; the
    ``[api]`` load only warns about those. So are entries that together span more than
    :data:`_PROXY_SPAN_LIMIT` budget keys of one family, more than a ``/16`` of IPv4 or a ``/48``
    of IPv6. An IPv4-mapped entry is read as the IPv4 range it names, the form
    :func:`_hop_readings` hands the walk, so one proxy matches in either spelling."""
    if value is None:
        return ()
    if isinstance(value, str):
        # Its own message: a MEFOR_VALUE_* variable is always text, so "must be a list" alone
        # would send an operator looking for a list syntax the variable cannot hold.
        raise ValueError(
            "Http trusted_proxies must be a list of proxy addresses or CIDR networks, and it is "
            "text (value withheld). An env() value from a MEFOR_VALUE_* variable is always text: "
            "write the list in environments/<env>.toml, or list the proxies in the config"
        )
    if not isinstance(value, (list, tuple)):
        raise ValueError(
            "Http trusted_proxies must be a list of proxy addresses or CIDR networks, "
            "e.g. trusted_proxies=['10.0.0.5']"
        )
    for index, entry in enumerate(value):
        if not isinstance(entry, str):
            raise ValueError(f"Http trusted_proxies item {index} must be a string (value withheld)")
    return _validated_proxy_networks(tuple(value))


@functools.lru_cache(maxsize=64)
def _validated_proxy_networks(value: tuple[str, ...]) -> tuple[_ProxyNetwork, ...]:
    """:func:`trusted_proxy_networks` for a list already known to hold strings. Cached, because
    ``GET /security/posture`` and each start and reload audit read every listener's list again on
    the event loop, and a list the span limit admits may hold 65,536 entries; a refusal raises, so
    it is never cached and every read refuses it again."""
    networks: list[_ProxyNetwork] = []
    for index, entry in enumerate(value):
        parsed = _parsed_proxy_or_none(entry)
        if parsed is None:
            # Raised outside the parse's handler and never quoted: _parse_trusted_proxy's message
            # echoes the entry, and no factory refusal may quote a configured value (vault BACKLOG
            # #3249, #3765). Its advice is also the API's, about uvicorn, which this listener is not.
            raise ValueError(
                f"Http trusted_proxies item {index} {_refused_entry_reason(entry)}; it is refused "
                "by the rule [api].trusted_proxies follows (value withheld)"
            )
        networks.append(_ipv4_meaning(ipaddress.ip_network(parsed)))
    whole_family, _ = _classify_proxy_entries(value)
    if whole_family:
        raise ValueError(
            "Http trusted_proxies entries together trust a whole address family, as the refused "
            "'*' does, so every client would count as a proxy and could choose its own "
            "failed-attempt budget key. List the reverse proxy's exact address(es) instead "
            "(values withheld)."
        )
    v4 = [network for network in networks if isinstance(network, ipaddress.IPv4Network)]
    v6 = [network for network in networks if isinstance(network, ipaddress.IPv6Network)]
    # A key is an IPv4 address or an IPv6 /64, so an IPv6 range counts its /64s, a host as one,
    # except where it overlaps a prefix whose addresses each key on themselves.
    spans = (
        (4, "/16", sum(n.num_addresses for n in ipaddress.collapse_addresses(v4))),
        (6, "/48", sum(_v6_key_count(n) for n in ipaddress.collapse_addresses(v6))),
    )
    for version, floor, keys in spans:
        if keys > _PROXY_SPAN_LIMIT:
            raise ValueError(
                f"Http trusted_proxies entries together span more than a {floor} of IPv{version}. "
                "Every host inside a listed range may write its own X-Forwarded-For and so choose "
                "its own failed-attempt budget key. List the reverse proxy's exact address(es), or "
                f"ranges that together stay within a {floor} (values withheld)."
            )
    return tuple(networks)


def _v6_key_count(network: ipaddress.IPv6Network) -> int:
    """How many budget keys an IPv6 range holds: its ``/64`` networks, or, where it overlaps an
    IPv4-embedding prefix, where a key is an address or an embedded IPv4 client, its addresses,
    which bound the keys there. Inside 6to4 a key is one ``/48``, its IPv4 holder's site."""
    if network.subnet_of(_SIX_TO_FOUR):
        return max(1, network.num_addresses >> 80)
    if any(network.overlaps(prefix) for prefix in _IPV4_EMBEDDING_PREFIXES):
        return network.num_addresses
    return max(1, network.num_addresses >> (128 - _IPV6_KEY_PREFIX))


class _ProxyMatcher:
    """Whether an address falls inside a listed proxy network, by bisecting the collapsed ranges of
    its family. The span limit allows 65,536 single-host entries, and the walk asks once per hop on
    the event loop, so a linear scan of the list would cost a padded header millions of checks."""

    __slots__ = ("_ends", "_starts")

    def __init__(self, networks: tuple[_ProxyNetwork, ...]) -> None:
        v4 = [n for n in networks if isinstance(n, ipaddress.IPv4Network)]
        v6 = [n for n in networks if isinstance(n, ipaddress.IPv6Network)]
        # collapse_addresses sorts and merges, so the ranges are disjoint and ascending.
        families: dict[int, list[_ProxyNetwork]] = {
            4: list(ipaddress.collapse_addresses(v4)),
            6: list(ipaddress.collapse_addresses(v6)),
        }
        self._starts = {v: [int(n.network_address) for n in c] for v, c in families.items()}
        self._ends = {v: [int(n.broadcast_address) for n in c] for v, c in families.items()}

    def __contains__(self, address: _HopAddress) -> bool:
        starts = self._starts[address.version]
        value = int(address)
        index = bisect.bisect_right(starts, value) - 1
        return index >= 0 and value <= self._ends[address.version][index]


def _parsed_proxy_or_none(entry: str) -> _HopAddress | _ProxyNetwork | None:
    """``_parse_trusted_proxy(entry)``, or ``None`` where it refuses. The caller raises its own
    refusal outside this handler, so the parse's message, which quotes the entry, is not its
    ``__context__``."""
    try:
        return _parse_trusted_proxy(entry)
    except ValueError:
        return None


def _refused_entry_reason(entry: str) -> str:
    """Why ``_parse_trusted_proxy`` refused ``entry``, in words that never quote it. A refusal names
    the form only; the parse that decided it is ``_parse_trusted_proxy``'s, not this one's."""
    if entry == "*":
        return "is '*', which trusts every peer"
    if "%" in entry and ":" in entry:
        return "is an IPv6 entry with a zone, which no peer address carries"
    try:
        ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return "is not a valid IP address or CIDR network"
    return "has host bits set; list the proxy's own address, or the range's network address"


def _hop_readings(text: str) -> tuple[_HopAddress, ...]:
    """One ``X-Forwarded-For`` hop as the address or addresses it may name; empty when none.

    Reads a bare address, ``a.b.c.d:port``, ``[v6]`` and ``[v6]:port``. Anything else, ``unknown``
    and an empty hop included, is empty and never becomes a budget key. A bare IPv6 hop is
    ambiguous when its last group is decimal digits and dropping that group still leaves an
    address: ``2001:db8::1:1234`` is an address, and also ``2001:db8::1`` with a port. Such a hop
    yields both, the whole address first, as uvicorn reads it. The caller keys the budget on every
    reading but a phantom one (:func:`_client_readings`), so a client cannot escape its own budget
    by choosing an interface identifier that makes its hop ambiguous: one of the two readings is
    its real address, and that one is always charged. The bracketed form says where the address
    ends and yields one. Each address is read by :func:`_peer_address`."""
    host = text.strip(" \t")
    bracketed = host.startswith("[")
    if bracketed:
        inner, closed, rest = host[1:].partition("]")
        if not closed or (rest and not (rest[:1] == ":" and _HOP_PORT_RE.fullmatch(rest[1:]))):
            return ()
        host = inner
    elif host.count(":") == 1:
        host, _, port = host.partition(":")
        if not _HOP_PORT_RE.fullmatch(port):
            return ()
    address = _peer_address(host)
    if address is None and not bracketed and host.count(":") > 1:
        # One group too many to be an address, such as a full eight-group address and a port:
        # unambiguous, so read as that address alone rather than fall back to the socket peer.
        head, _, last = host.rpartition(":")
        if _HOP_PORT_RE.fullmatch(last):
            return () if (only := _peer_address(head)) is None else (only,)
    if address is None:
        return ()
    if not bracketed and host.count(":") > 1:
        # Checked only once the hop parsed, so the second parse runs for a bare IPv6 hop alone.
        head, _, last = host.partition("%")[0].rpartition(":")
        if _HOP_PORT_RE.fullmatch(last):
            other = _peer_address(head)
            if other is not None:
                return (address, other)
    return (address,)


def _peer_address(text: str | None) -> _HopAddress | None:
    """A plain address, a socket peer or a hop's host, normalised; ``None`` when it is not one.

    An IPv6 zone is dropped, as ``netaddr`` drops it from a socket peer, so the key and the
    recorded address never carry text after a ``%``. An IPv4-mapped address is read as its IPv4
    address, so a client keys one budget whichever spelling a dual-stack socket or proxy gives."""
    if text is None:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.scope_id is not None:
            address = ipaddress.IPv6Address(int(address))
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
    return address


def _budget_key(address: _HopAddress) -> str:
    """The failed-attempt budget key for ``address``: an IPv4 address as written, an IPv6 address
    as its ``/64``, so rotating addresses inside one ``/64`` mints no budget (BACKLOG #5525).

    An address in an IPv4-embedding prefix does not key on its ``/64``. Where the IPv4 client sits
    at a fixed place (:func:`_embedded_client`), it keys as that IPv4 address, so a client holds
    one budget whichever way it arrives: under NAT64's well-known ``64:ff9b::/96``, whose ``/64``
    holds unrelated clients, under Teredo, whose other bits a client may vary, and under 6to4,
    whose one IPv4 holder holds 65,536 ``/64`` networks. In the rest, NAT64's local-use
    ``64:ff9b:1::/48``, whose embedding depends on the operator's prefix length, and ``::/96``,
    the address keys on itself."""
    if isinstance(address, ipaddress.IPv4Address):
        return str(address)
    embedded = _embedded_client(address)
    if embedded is not None:
        return str(embedded)
    # The other three embedding prefixes all carry a fixed-place client, answered above.
    if address in _NAT64_LOCAL_USE or address in _IPV4_COMPATIBLE:
        return str(address)
    return str(ipaddress.IPv6Network((address, _IPV6_KEY_PREFIX), strict=False))


def _low_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)


def _embedded_client(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 client ``address`` carries at a fixed place, or ``None``: the low 32 bits under
    NAT64's well-known ``64:ff9b::/96``, Teredo's client field, or 6to4's ``2002:V4ADDR::/48``."""
    if address in _NAT64_WELL_KNOWN:
        return _low_ipv4(address)
    teredo = address.teredo
    if teredo is not None:
        return teredo[1]
    return address.sixtofour


def _is_client_ipv4(address: ipaddress.IPv4Address) -> bool:
    # One rule with the [api] entry reader's, so a change to it reaches both.
    return not _not_a_host_address(str(address))


def _is_phantom(address: _HopAddress) -> bool:
    """Whether no client can hold ``address``: an embedding whose IPv4 client, or Teredo server,
    is in space no host sends from, an IPv4-compatible address other than ``::1`` whose IPv4 is,
    or an address in the unassigned rest of ``::/8``, NAT64's well-known ``/48`` outside its
    ``/96`` included (see :data:`_IETF_RESERVED`)."""
    if isinstance(address, ipaddress.IPv4Address):
        return False
    teredo = address.teredo
    if teredo is not None:
        return not (_is_client_ipv4(teredo[0]) and _is_client_ipv4(teredo[1]))
    embedded = _embedded_client(address)
    if embedded is not None:
        return not _is_client_ipv4(embedded)
    if address in _IPV4_COMPATIBLE:
        return not address.is_loopback and not _is_client_ipv4(_low_ipv4(address))
    return address in _IETF_RESERVED and address not in _NAT64_LOCAL_USE


def _network_64(address: _HopAddress) -> int:
    """The ``/64`` an address sits in, as an integer; an IPv4 address as its mapped form."""
    value = int(address)
    if isinstance(address, ipaddress.IPv4Address):
        value |= _IPV4_MAPPED_BASE
    return value >> (128 - _IPV6_KEY_PREFIX)


def _client_readings(readings: tuple[_HopAddress, ...]) -> tuple[_HopAddress, ...]:
    """The readings of the client's hop the budget is keyed on: every reading, except that of an
    ambiguous hop's two, one that no client can hold (:func:`_is_phantom`) is dropped where the
    other is one a client can hold and both share a ``/64`` (BACKLOG #5525).

    Each reading is otherwise checked and charged, so a client cannot leave its own budget. A
    misreading such as ``64:ff9b::c000``, from the NAT64 hop ``64:ff9b::c000:221`` without its
    last group, would fold to the IPv4 key ``0.0.192.0``, which every NAT64 client whose
    IPv4 starts ``192.0`` and whose hop ends in decimal digits misreads to too, so one of them could spend
    that key's budget and so refuse the rest. A real address is never dropped, since no client
    holds a phantom one; and the kept reading sits in the same ``/64`` as the dropped one, so a
    host that could send from the dropped address keys no budget it could not reach by sending
    from the kept one."""
    if len(readings) != 2:
        return readings
    kept = tuple(reading for reading in readings if not _is_phantom(reading))
    if len(kept) == 1 and _network_64(readings[0]) == _network_64(readings[1]):
        return kept
    return readings


def _peer_budget_key(peer_host: str | None, address: _HopAddress | None = None) -> str:
    """The budget key for a socket peer, read as a forwarded client is read: normalised by
    :func:`_peer_address` and keyed by :func:`_budget_key`, so one host never holds two budgets
    under two spellings. A peer that is not an address keys as it was given, or ``unknown``.
    ``address`` is the peer already parsed, where the caller has it."""
    if address is None:
        address = _peer_address(peer_host)
    if address is None:
        return peer_host or "unknown"
    return _budget_key(address)


def _with_forwarded(text: str, exc: HttpRequestError) -> str:
    """``text`` with the forwarded client address the refusal keyed on, where it had one, so an
    audit detail and an event reason record it the same way beside the socket peer (BACKLOG #5525)."""
    if exc.forwarded_for is None:
        return text
    return f"{text}; forwarded_for={exc.forwarded_for}"


def _subjects_by_issuer(subjects: Any) -> dict[str, dict[str, str]]:
    """``intake_client_subjects`` as the matcher reads it: issuer DN -> each name mapped to itself.

    The ``Http`` factory has already validated the shape (vault BACKLOG #2287). This refuses a value
    that is not a table at all, such as the retired flat list, so a ``Source`` built some other way
    fails at construction rather than denying every peer with nothing in the log."""
    if not subjects:
        return {}
    if not isinstance(subjects, Mapping) or any(
        not isinstance(names, list | tuple) for names in subjects.values()
    ):
        raise ValueError(
            "HTTP source intake_client_subjects must be a table keyed by the issuing CA's DN, each "
            "naming a list of subjects, not a flat list (vault BACKLOG #2287)"
        )
    return {str(issuer): {str(n): str(n) for n in names} for issuer, names in subjects.items()}


def _client_issuer_index(
    name: str, cadata: str | None, subjects: Mapping[str, object]
) -> IssuerIndex | None:
    """Index the client CAs this listener loaded, and warn about an issuer key that cannot match.

    ``cadata`` is the text the SSL context loaded, or ``None`` when it loaded none. A key
    naming no loaded CA, or naming two loaded CAs with one subject and different keys, would deny
    every certificate under it with nothing in the log, so each one is warned about here, as the API
    does for ``[api].tls_client_cert_identities``, as is a loaded certificate that is no CA with a
    loaded CA's subject (:meth:`~messagefoundry.pki.IssuerIndex.namesake_warnings`). Raises
    ``ValueError``, refusing the start, when :class:`~messagefoundry.pki.IssuerIndex` refuses the
    file; what it compares with the TLS library is stated there."""
    if cadata is None:
        return None
    # Lazy: pki pulls in cryptography, which a listener without mtls_subject never needs.
    from messagefoundry.pki import IssuerIndex

    index = IssuerIndex(cadata, label=f"HTTP listener {name!r}: tls_ca_file")
    for issuer in index.unmatched_keys(subjects):
        # pki's own reason names the API's file, so this line states both causes in this
        # listener's terms rather than quote it.
        logger.warning(
            "HTTP source %s: intake_client_subjects issuer %r names no CA certificate loaded from "
            "tls_ca_file, or names several with one subject and different keys; no client "
            "certificate is admitted under it",
            name,
            issuer,
        )
    for warning in index.namesake_warnings():
        logger.warning("HTTP source %s: tls_ca_file %s", name, warning)
    return index


class HttpSource(SourceConnector):
    """Listen for inbound HTTP/1.1 requests, commit each POSTed body to the ingress stage via the
    pipeline handler, and return a ``202`` respond-with-receipt once it is durably committed (ADR 0023).

    A faithful :class:`~messagefoundry.transports.mllp.MLLPSource` sibling: same bind/stop lifecycle,
    per-connection IP allowlist, inbound TLS, and on-by-default ``connection_event`` plumbing."""

    #: The 202 carries the committed message id, so the runner starts this source with the receipt handler.
    wants_receipt: ClassVar[bool] = True

    def __init__(self, config: Source) -> None:
        s = config.settings
        # The bind interface is injected from the service's [inbound].bind_host (authors never set a
        # host on an inbound). Fall back to loopback for a missing/None value — never bind all
        # interfaces (0.0.0.0) by accident. The runner's exposed-gate refuses a non-loopback bind
        # without TLS (check_http_tls_exposure). See docs/CONNECTIONS.md.
        self.host: str = s.get("host") or "127.0.0.1"
        self.port: int = port_setting(s["port"], transport="HTTP source")
        #: How this source names itself in a log line.
        self._log_name: str = config.name or f"{self.host}:{self.port}"
        # Caps below: key absent → secure default; None/0 in any spelling (including the string "0"
        # an uncast env() yields) → disabled where allowed; a negative or NaN → refused at build
        # (BACKLOG #1872).
        self.max_connections: int | None = positive_cap(
            s.get("max_connections", DEFAULT_MAX_CONNECTIONS),
            int,
            knob="max_connections",
            transport="HTTP source",
        )
        self.receive_timeout: float | None = positive_cap(
            s.get("receive_timeout", DEFAULT_RECEIVE_TIMEOUT),
            float,
            knob="receive_timeout",
            transport="HTTP source",
        )
        self.max_body_bytes: int | None = positive_cap(
            s.get("max_body_bytes", DEFAULT_MAX_BODY_BYTES),
            int,
            knob="max_body_bytes",
            transport="HTTP source",
        )
        self.max_header_bytes: int = _header_cap(s.get("max_header_bytes"))
        # Message-rate pacing (BACKLOG #1114), read through the shared helper so this connector
        # cannot drift from MLLP on what "unset" means. Absent -> OFF, unlike the caps above. The
        # port changed REACHABILITY, never the default -- a stock HTTP inbound still has no bound.
        self.max_messages_per_second, self.message_burst = _pacing_settings(
            s, transport="HTTP source"
        )
        #: ONE bucket for the whole listener, not one per connection. This connector answers exactly
        #: one request per connection (build_response hardcodes Connection: close), so a
        #: per-connection bucket would be charged once and thrown away — a rate knob that paced
        #: nothing. The listener scope is what makes the control real here, and it is also a TIGHTER
        #: bound than MLLP's: N concurrent MLLP peers may sustain N times the rate between them,
        #: N concurrent HTTP partners share one budget. Driven with deficit()/charge() rather than
        #: pace()/settle() for the same reason — there is no next read on this connection to settle
        #: against. Distinct from the injected `intake_rate_limiter`, which REFUSES failed auth
        #: attempts with a 429; this one only ever waits.
        self._pacer = _MessagePacer.for_rate(
            self.max_messages_per_second, self.message_burst, name=config.name or ""
        )
        # Per-connection peer-IP allowlist (Tier 4): refuse a non-listed peer at accept (fail-closed).
        # Absent/empty = no restriction. Mirrors MLLPSource.
        sa = s.get("source_ip_allowlist")
        self.source_ip_allowlist: list[str] | None = [str(x) for x in sa] if sa else None
        # Per-connection inbound TLS (present a server cert; opt-in mTLS via tls_ca_file), built once at
        # construction so a bad cert/key fails at build. None when tls is off → plaintext, byte-identical.
        # The client trust store's exact text, handed back by the builder so the issuer index below
        # reads the bytes the context loaded and never re-reads tls_ca_file (vault BACKLOG #2287).
        loaded_client_ca: list[str] = []
        self._ssl: ssl.SSLContext | None = _mllp_ssl_context(
            s,
            server=True,
            name=config.name or "",
            listener_family="HTTP listener",
            on_client_ca=loaded_client_ca.append,
        )
        # Failed TLS handshakes and their throttled `tls_handshake_failed` events (vault BACKLOG
        # #3302), counted with the peer on every loop, as the MLLP listener's are: by `_start_tls`
        # on the stdlib loop, and by `_handshake_accepted` under `_AcceptingServer` (BACKLOG
        # #2479). This listener never hooks the context (`HandshakeFailures.watch`).
        self._tls_failures = HandshakeFailures(self._emit_tls_failure)
        # True while this listener runs TLS handshakes itself with `start_tls`, after admission
        # (BACKLOG #2479); set at start() from the running loop, see `_upgrades_tls_itself`. False
        # with TLS on means `_AcceptingServer` instead.
        self._upgrade_tls = False
        # The `_handshake_accepted` tasks still inside the loop's TLS handshake, which stop() cancels
        # so their sockets close at once rather than at the handshake bound (BACKLOG #2479).
        self._handshakes: set[asyncio.Task[None]] = set()
        # Intake authentication (ADR 0154 D6) — a PEER control: it authorises SUBMITTING a message on
        # this inbound, mints no identity and opens no session. Defaults to "none", which makes every
        # path below a no-op and every shipped configuration byte-identical. The env() refs are already
        # resolved to strings by the time a Source reaches here (_source_config → resolve_env_settings).
        self.intake_auth: str = str(s.get("intake_auth") or "none")
        self._intake_keys: tuple[str | None, str | None] = (
            s.get("intake_api_key"),
            s.get("intake_api_key_next"),
        )
        self.intake_api_key_header: str = str(s.get("intake_api_key_header") or "x-api-key").lower()
        #: The one header this listener reads a credential from, or ``None`` when it reads none:
        #: ``mtls_subject`` reads the peer certificate, and ``none`` reads nothing. Both the read and
        #: the repeat check (BACKLOG #2051) go through this one name, so they cannot disagree.
        self._credential_header: str | None = {
            "api_key": self.intake_api_key_header,
            "bearer": "authorization",
        }.get(self.intake_auth)
        #: The same name with ``_`` read as ``-``, the form ``HttpRequest.repeated`` is keyed by.
        self._credential_header_folded: str | None = (
            self._credential_header.replace("_", "-") if self._credential_header else None
        )
        #: Issuer DN -> qualified subject names, each name mapped to itself (vault BACKLOG #2287).
        #: Matched through ``client_cert_principal_under_issuer``, the API's own matcher, so a subject
        #: counts only under the loaded CA that signed the leaf, with that helper's deny-by-default and
        #: qualified CN/SAN namespacing, rather than a second matcher that could disagree with it.
        self._intake_subjects: dict[str, dict[str, str]] = _subjects_by_issuer(
            s.get("intake_client_subjects")
        )
        self.intake_auth_health: str = str(s.get("intake_auth_health") or "require")
        #: The reverse proxies whose ``X-Forwarded-For`` the failed-attempt budget may key on, under
        #: ``api_key`` and ``bearer`` only (BACKLOG #5525). Empty, the default, keys on the socket
        #: peer, read by :func:`_peer_budget_key`. At least the allowlist, the connection caps and
        #: the audit and event peer column stay on the socket peer; a refusal adds the forwarded
        #: address beside it.
        self._trusted_proxies: tuple[_ProxyNetwork, ...] = trusted_proxy_networks(
            s.get("trusted_proxies")
        )
        self._proxy_matcher = _ProxyMatcher(self._trusted_proxies)
        # Synchronous captured-downstream reply (ADR 0154 D4). reply_from's presence is the mode
        # switch; absent, every path below is byte-identical to the shipped 202 slice (AC-8).
        self.reply_from: str | None = s.get("reply_from") or None
        self.reply_timeout: float = reply_seconds(s, "reply_timeout")
        self.reply_on_timeout: str = str(s.get("reply_on_timeout") or "504")
        self.reply_content_type: str = str(s.get("reply_content_type") or "passthrough")
        self.reply_on_empty: str = str(s.get("reply_on_empty") or "204")
        self.reply_write_timeout: float = reply_seconds(s, "reply_write_timeout")
        self._server: asyncio.Server | _AcceptingServer | None = None
        #: The runner's receipt handler (``wants_receipt``), never the generic InboundHandler.
        self._handler: ReceiptHandler | None = None
        # vault BACKLOG #2606: the per-host cap SHIPS OFF here, unlike on the MLLP, raw-TCP and X12
        # listeners. This connector answers one request per connection, so behind a reverse proxy
        # every partner arrives from one address and a per-host cap would be the listener's whole
        # capacity. An operator who sees real client addresses can set one.
        self.max_connections_per_host: int | None = positive_cap(
            s.get("max_connections_per_host"),
            int,
            knob="max_connections_per_host",
            transport="HTTP source",
        )
        # vault BACKLOG #4888: the per-host bound that DOES ship on, for the handshake phase only.
        self.max_handshakes_per_host: int | None = positive_cap(
            s.get("max_handshakes_per_host", DEFAULT_MAX_HANDSHAKES_PER_HOST),
            int,
            knob="max_handshakes_per_host",
            transport="HTTP source",
        )
        self._admission = ListenerAdmission(
            transport="HTTP",
            max_connections=self.max_connections,
            max_connections_per_host=self.max_connections_per_host,
            source_ip_allowlist=self.source_ip_allowlist,
            name=config.name or "",
            max_handshakes_per_host=self.max_handshakes_per_host,
        )
        # Live client writers + handler tasks so stop()/reload can actively close established
        # connections and bound the wait (mirrors MLLPSource, review H-2 / #55).
        self._clients: set[asyncio.StreamWriter] = set()
        self._client_tasks: set[asyncio.Task[None]] = set()
        #: Which loaded client CA signed a peer's leaf. Only ``mtls_subject`` reads it, so no other
        #: mode pays for parsing the trust store. ``None`` there means no client CA was loaded, and
        #: then no certificate names an issuer, so every one is denied. Built after every check
        #: in this constructor that can refuse it, because it may warn (BACKLOG #2749's rule).
        self._issuer_index: IssuerIndex | None = (
            _client_issuer_index(
                self._log_name,
                loaded_client_ca[0] if loaded_client_ca else None,
                self._intake_subjects,
            )
            if self.intake_auth == "mtls_subject"
            else None
        )
        ranges = sum(1 for network in self._trusted_proxies if network.num_addresses > 1)
        if ranges:
            # The [api] list's ranges are named as a loosening at serve; this list's are warned
            # about here, counted and never quoted (BACKLOG #5525).
            logger.warning(
                "HTTP source %s: trusted_proxies holds %d range(s); every host inside one is "
                "trusted as a proxy and may choose its own failed-attempt budget key",
                self._log_name,
                ranges,
            )
        if self.max_body_bytes is None:
            # Turning the body cap off is documented, so it is allowed, but never silent (BACKLOG
            # #2749, as FileSource does for its caps). Logged after every check in this constructor,
            # so a source it refuses has not logged it. The line names the setting, never its value.
            logger.warning(
                "HTTP source %s: max_body_bytes is off, so a request body of any declared size is "
                "read whole; set a positive value to bound it",
                self._log_name,
            )

    async def start(
        self,
        handler: ReceiptHandler | InboundHandler,
        *,
        leader_gate: Callable[[], bool] | None = None,
    ) -> None:
        # leader_gate is ignored: a listen source runs on every node (each binds its own endpoint), so
        # there is no shared-resource double-read to gate. Accepted only so the runner's call is uniform.
        # wants_receipt makes the runner pass its receipt handler here (BACKLOG #2105). The parameter
        # keeps the base class's InboundHandler beside it only so the override stays substitutable;
        # require_receipt refuses any other handler here, before a single message is accepted.
        self._handler = require_receipt(handler, source="HTTP source")
        self._admission.stopping = False  # a restart of this same instance serves again
        guard_accepts()  # see messagefoundry.proactor_accept
        self._tls_failures.open()
        # BACKLOG #2479, the shape BACKLOG #1606 fixed on MLLP. A TLS listener accepts PLAIN TCP
        # and admits each socket before its handshake, so the allowlist, both connection caps and
        # the handshake budget run before any TLS byte, and a socket in its handshake holds a slot.
        # On the stdlib loop it upgrades an admitted socket itself; `_upgrades_tls_itself` says why
        # other loops, uvloop among them, get `_AcceptingServer` instead. Both bound the handshake
        # at `_TLS_HANDSHAKE_TIMEOUT`, read at each handshake so a test can shorten it. The close
        # exchange keeps asyncio's default on both paths, unlike MLLP's: a `reply_from` answer can
        # be partner-sized, and its tail may still be queued when the close starts (see
        # `_drain_budget`).
        self._upgrade_tls = self._ssl is not None and _upgrades_tls_itself(
            asyncio.get_running_loop()
        )
        if self._ssl is None:
            self._server = await asyncio.start_server(self._on_client, self.host, self.port)
            return
        # This listener counts its own failures on both paths and never hooks its context. Unhooked
        # anyway, as MLLPSource.start does, so a context something else hooked cannot count each
        # failure a second time, with no peer.
        self._tls_failures.unwatch(self._ssl)
        if self._upgrade_tls:
            self._server = await asyncio.start_server(self._on_tls_accept, self.host, self.port)
            return
        self._server = _AcceptingServer(
            await _bind_tcp(self.host, self.port, transport="HTTP"),
            self._on_tls_socket,
            name=self._log_name,
            transport="HTTP",
        )

    def _on_tls_socket(self, sock: socket.socket) -> None:
        """Take a socket `_AcceptingServer` accepted, in its own task (BACKLOG #2479), as
        ``MLLPSource._on_tls_socket`` does. The socket stays in ``unwrapped`` while this listener
        still owns it, so the done callback can close it if the task ends first, even cancelled
        before its first step."""
        unwrapped = [sock]
        task = asyncio.get_running_loop().create_task(self._handshake_accepted(sock, unwrapped))
        self._client_tasks.add(task)
        task.add_done_callback(lambda done: self._accepted_task_done(done, unwrapped))

    def _accepted_task_done(self, task: asyncio.Task[None], unwrapped: list[socket.socket]) -> None:
        """`_client_task_done` for a `_handshake_accepted` task: drop it, close a socket the TLS
        layer never took, and log a fault the task did not handle itself."""
        self._client_tasks.discard(task)
        for sock in unwrapped:
            sock.close()
        if not task.cancelled() and (exc := task.exception()) is not None:
            logger.error("HTTP client connection task failed: %s", safe_exc(exc))

    async def _handshake_accepted(
        self, sock: socket.socket, unwrapped: list[socket.socket]
    ) -> None:
        """Admit a socket `_AcceptingServer` accepted, then run its TLS handshake through the loop,
        and hand a completed one to `_on_client` (BACKLOG #2479).

        ``MLLPSource._handshake_accepted`` states each step's reasoning once: who owns the socket
        when, the DEBUG-only failure line, a failure before the transport holds the socket, and a
        clean close during the handshake. Three differences. An admitted socket counts against
        ``max_handshakes_per_host`` until its handshake ends, however it ends (vault BACKLOG
        #4888). And no ``ssl_shutdown_timeout`` is passed, so the TLS close exchange keeps
        asyncio's default, as on this listener's other path; start() says why. And a cancellation
        by stop() is followed by an abort of the TLS transport."""
        assert self._ssl is not None
        try:
            peer = _AcceptedPeer(sock)
        except OSError as exc:
            # Gone before anything read it; the done callback closes it.
            logger.debug("HTTP connection gone before admission: %s", safe_exc(exc))
            return
        peer_host = _peer_host(peer)
        refusal = self._admission.check(peer, peer_host, handshake=True)
        if refusal is not None:
            sock.close()
            if refusal.kind is not None:
                await self._emit_event(refusal.kind, peer_host=peer_host, reason=refusal.reason)
            return
        epoch = self._admission.admit(peer_host)
        handed_over = False
        try:
            loop = asyncio.get_running_loop()
            reader = asyncio.StreamReader()
            protocol = _HandshakeProtocol(reader)
            task = asyncio.current_task()
            assert task is not None  # always: `_on_tls_socket` runs this as a task
            self._handshakes.add(task)
            # See `MLLPSource._handshake_accepted`: this runs only once the call below first
            # suspends, by when the TLS layer's transport holds the socket.
            disown = loop.call_soon(unwrapped.clear)
            try:
                with self._admission.handshake(peer_host, epoch):
                    transport, _ = await loop.connect_accepted_socket(
                        lambda: protocol,
                        sock,
                        ssl=self._ssl,
                        ssl_handshake_timeout=_TLS_HANDSHAKE_TIMEOUT,
                    )
                unwrapped.clear()  # the transport owns the socket now
            except OSError as exc:
                # Out of `_handshakes` before the report below awaits, so a stop() that cancels the
                # tasks still in their handshake cannot cancel a report already in flight.
                self._handshakes.discard(task)
                if unwrapped:
                    # Not a handshake failure, so not counted; the done callback closes the socket.
                    logger.debug(
                        "HTTP connection from %s could not be handed to TLS: %s",
                        peer.get_extra_info("peername"),
                        safe_exc(exc),
                    )
                    return
                logger.debug(
                    "TLS handshake on HTTP from %s did not complete: %s",
                    peer.get_extra_info("peername"),
                    safe_exc(exc),
                )
                if not isinstance(exc, HUNG_UP):  # as in `_start_tls`
                    await self._tls_failures.note(peer_host, handshake_cause(exc))
                return
            except asyncio.CancelledError:
                # stop() cancels a task still in `_handshakes`. Where the handshake completed
                # before the task stepped, in either order against stop(), the cancellation makes
                # `connect_accepted_socket` close the TLS transport with a close exchange, which a
                # silent peer can hold open for asyncio's 30 s default after stop() returns. That
                # close is followed at once by an abort.
                if protocol.tls_transport is not None:
                    protocol.tls_transport.abort()
                raise
            finally:
                self._handshakes.discard(task)
                disown.cancel()
            if not protocol.connected:
                logger.debug(
                    "TLS connection on HTTP from %s closed during its handshake",
                    peer.get_extra_info("peername"),
                )
                return
            writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            handed_over = True
            await self._on_client(reader, writer, slot=(peer_host, epoch))
        finally:
            if not handed_over:
                self._admission.release(peer_host, epoch)

    def _on_tls_accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Take a new TLS-listener socket in plain TCP, then hand it to `_on_client` (BACKLOG #2479).

        Deliberately NOT a coroutine, so reading is paused before the loop arms its first read and
        the ClientHello stays in the kernel until ``start_tls``. ``MLLPSource._on_tls_accept``
        states the reasoning once. The task and writer are registered here, so stop() closes a
        socket still in its handshake."""
        # A stream's transport reads as well as writes; typeshed types the attribute write-only.
        cast(asyncio.Transport, writer.transport).pause_reading()
        self._clients.add(writer)
        task = asyncio.get_running_loop().create_task(self._on_client(reader, writer))
        self._client_tasks.add(task)
        task.add_done_callback(lambda done: self._client_task_done(done, writer))

    def _client_task_done(self, task: asyncio.Task[None], writer: asyncio.StreamWriter) -> None:
        """Drop a finished TLS client task, and close its socket if the task was cancelled or
        failed: asyncio does that for a coroutine accept callback, and `_on_tls_accept` is not one.
        A task cancelled before its first step never ran its own ``finally``, so its writer is
        dropped from ``_clients`` here too."""
        self._client_tasks.discard(task)
        if task.cancelled():
            self._clients.discard(writer)
            writer.close()
            return
        exc = task.exception()
        if exc is not None:
            logger.error("HTTP client connection task failed: %s", safe_exc(exc))
            self._clients.discard(writer)
            writer.close()

    async def _start_tls(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer_host: str | None
    ) -> bool:
        """Run the TLS handshake on an admitted socket; ``False`` when it did not complete.

        The same upgrade as ``MLLPSource._start_tls``, whose docstring states each guard once: the
        handshake bound, the DEBUG-only failure line, the writer a clean close leaves with no
        transport, and the reader moved onto the TLS transport. The close-exchange bound is left
        at asyncio's default; start() says why. A hang-up is not counted as a failure; a TLS error
        and the handshake bound are."""
        assert self._ssl is not None
        raw = writer.transport
        try:
            await writer.start_tls(self._ssl, ssl_handshake_timeout=_TLS_HANDSHAKE_TIMEOUT)
        except OSError as exc:
            logger.debug(
                "TLS handshake on HTTP from %s did not complete: %s",
                writer.get_extra_info("peername"),
                safe_exc(exc),
            )
            if not isinstance(exc, HUNG_UP):
                await self._tls_failures.note(peer_host, handshake_cause(exc))
            return False
        except AttributeError:
            if not _lost_its_transport(writer):
                raise
        if _lost_its_transport(writer):
            writer._transport = raw  # type: ignore[attr-defined]  # see MLLPSource._start_tls
            logger.debug(
                "TLS connection on HTTP from %s closed during its handshake",
                raw.get_extra_info("peername"),
            )
            return False
        reader._transport = writer.transport  # type: ignore[attr-defined]  # see MLLPSource._start_tls
        return True

    @property
    def sockport(self) -> int:
        """The actual bound port (useful when configured with port 0 in tests)."""
        assert self._server is not None
        port: int = self._server.sockets[0].getsockname()[1]
        return port

    async def stop(self) -> None:
        # Stop accepting NEW connections (this alone does not close established ones). A connection
        # reaching _on_client from here is refused unread, and no handshake failure is counted.
        self._admission.stopping = True
        self._tls_failures.close()
        if self._server is not None:
            self._server.close()
        # ADR 0154 D5 — the PRE-CLOSE drain phase, and its position is the whole point (AC-10).
        #
        # Waking blocked waiters must happen BEFORE the writers below are closed. Revision 1 of the
        # ADR promised both the 503 and the existing close-first ordering; those are mutually
        # exclusive. A 503 written after close() lands on a dead transport, and post-close asyncio
        # typically DISCARDS the write with no exception at all — so _write_safely's
        # `except (TimeoutError, OSError)` never even sees it and the demoted caller gets a bare
        # connection reset instead of the answer the HA argument depends on.
        #
        # Each woken turn resolves `shutting_down` and writes its own 503 + Retry-After through its
        # still-open writer on the way out, inside the same bounded grace the teardown already has.
        # No-op when nothing is armed, so a listener with no reply_from is byte-identical.
        if self.reply_drain is not None:
            self.reply_drain("shutting_down")
        # Close established clients BEFORE awaiting the server (server.wait_closed() hangs on py3.12.1+
        # waiting for in-flight handlers of a peer holding its connection open). A request mid-handler
        # still finishes its commit (the body is durably stored before the 202, so at-least-once holds).
        # Then await the connection tasks with a bounded grace and cancel any stragglers (review H-2).
        try:
            # A socket still in its TLS handshake is this listener's own from its accept on
            # (BACKLOG #2479). Where it upgrades TLS itself it is in `_clients` (`_on_tls_accept`),
            # so this loop closes it and its handshake fails rather than completing mid-stop. Under
            # `_AcceptingServer` its task is in `_handshakes`, and cancelling that task makes
            # `connect_accepted_socket` close the socket; `_handshake_accepted` aborts one whose
            # handshake had already completed.
            for writer in list(self._clients):
                writer.close()
            for handshake in list(self._handshakes):
                handshake.cancel()
            pending = [task for task in self._client_tasks if not task.done()]
            if pending:
                _done, still_running = await asyncio.wait(pending, timeout=_CLIENT_SHUTDOWN_GRACE)
                for task in still_running:
                    task.cancel()
                if still_running:
                    await asyncio.gather(*still_running, return_exceptions=True)
            self._clients.clear()
            self._client_tasks.clear()
            self._handshakes.clear()
            # Report the handshake failures a trailing event still held (vault BACKLOG #3302).
            # `flush` says why it does nothing once a restart has begun.
            await self._tls_failures.flush()
        finally:
            # Even when this stop() is cancelled: a task cancelled past its grace never released.
            self._admission.reset()
        # Bound wait_closed() so a Windows ProactorEventLoop overlapped-op wedge can't hang teardown on
        # the suite's shared session loop (#55, mirrors MLLPSource.stop()). The listener is closed and
        # every client task is resolved, so a wait_closed() past the grace is an OS wedge — abandoning it
        # is safe (the socket is closed) and bounds an otherwise infinite teardown.
        if self._server is not None:
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=_CLIENT_SHUTDOWN_GRACE)
            except TimeoutError:
                logger.warning("HTTP server.wait_closed() exceeded shutdown grace; abandoning")
            self._server = None

    @property
    def tls_handshake_failures(self) -> int:
        """Failed TLS handshakes this listener has seen since it was built, outside its stop()s
        (vault BACKLOG #3302)."""
        return self._tls_failures.count

    async def _emit_tls_failure(self, peer_host: str | None, reason: str) -> None:
        await self._emit_event("tls_handshake_failed", peer_host=peer_host, reason=reason)

    async def _emit_event(
        self, kind: str, *, peer_host: str | None = None, reason: str | None = None
    ) -> None:
        """Fire one connection event (Corepoint-style log, #46) to the injected sink, **fail-soft**: a
        capture/store hiccup must NEVER raise into the per-client loop. No-op when the sink is unset."""
        sink = self.on_connection_event
        if sink is None:
            return
        try:
            await sink(kind, peer_host, reason)
        except Exception as exc:  # swallow + log; a capture bug can't drop an HTTP client
            logger.warning("HTTP connection-event emit failed: %s", safe_exc(exc))

    # ---- intake authentication (ADR 0154 D6) ---------------------------------------------------
    #
    # Every refusal below is PRE-INGRESS: it happens before the pipeline handler runs, so nothing is
    # committed and count-and-log is intact — there is no accepted message to account for. That is
    # only true because the budget is consulted read-only and charged on failure; a limiter that
    # charged per attempt would refuse authenticated traffic here, and THAT would be silent loss.

    def _rate_limit_refusal(self, peers: tuple[str, ...]) -> HttpRequestError | None:
        """The ``429`` if any of ``peers`` has spent its failed-attempt budget, else ``None``.

        Consulted **read-only** and **before** any credential comparison: the point of the budget is
        to bound guessing, and a successful authentication must never consume it. ``peers`` holds
        one key, or two for an ambiguous forwarded hop (BACKLOG #5525).
        """
        limiter = self.intake_rate_limiter
        if limiter is None or all(limiter.check(peer) for peer in peers):
            return None
        return HttpRequestError(
            429,
            "too many failed authentication attempts",
            kind="auth_rate_limited",
            headers={"Retry-After": "60"},
        )

    def _charged(self, peers: tuple[str, ...], refusal: HttpRequestError) -> HttpRequestError:
        """Charge one FAILED attempt against each of ``peers`` and hand the refusal straight back.

        Takes an already-built refusal rather than its parts so every ``kind=`` stays a literal at a
        visible ``HttpRequestError(...)`` call site. CI derives the whole ``connection_event``
        vocabulary by AST-walking for exactly that shape, so a kind hidden behind a helper's parameter
        would escape the check that it is declared in ``CONNECTION_EVENT_KINDS`` and ``docs/PHI.md``
        §7. An undeclared kind is then refused by the store at write time, and the event is lost.
        """
        if self.intake_rate_limiter is not None:
            for peer in peers:
                self.intake_rate_limiter.charge_failure(peer)
        return refusal

    def _note_intake_success(self, peers: tuple[str, ...]) -> None:
        if self.intake_rate_limiter is not None:
            for peer in peers:
                self.intake_rate_limiter.note_success(peer)

    def _authorize_peer_cert(
        self, writer: asyncio.StreamWriter, peer_host: str | None
    ) -> HttpRequestError | None:
        """``mtls_subject`` authentication, run at accept — **before a single byte is read**.

        The certificate is already verified against ``tls_ca_file`` by the TLS handshake, so all that
        is left is the subject binding the CA does not give us: ``tls_ca_file`` alone means "any
        certificate this CA ever signed".

        The subject is looked up only under the loaded CA whose key signed the leaf (vault BACKLOG
        #2287). With several CAs in ``tls_ca_file``, any of them can issue a listed subject, and
        without the issuer every one of those certificates was admitted as that partner.

        Worth noting as an architectural asymmetry: ADR 0083's blocker on the admin API was that stock
        uvicorn does not surface the peer certificate to the ASGI scope. ``HttpSource`` owns its own
        socket, so mTLS-as-identity is strictly *easier* here than there.
        """
        if self.intake_auth != "mtls_subject":
            return None
        peer = (_peer_budget_key(peer_host),)
        limited = self._rate_limit_refusal(peer)
        if limited is not None:
            return limited
        ssl_object = writer.get_extra_info("ssl_object")
        peercert = ssl_object.getpeercert() if ssl_object is not None else None
        if not peercert:
            # No verified chain presented at all — an AUTHENTICATION failure.
            return self._charged(
                peer,
                HttpRequestError(401, "intake authentication required", kind="intake_auth_failed"),
            )
        # Lazy, as _client_issuer_index's: pki pulls in cryptography.
        from messagefoundry.pki import peer_othernames_intact

        verified = {
            **peercert,
            VERIFIED_ISSUER_KEY: self._verified_issuer(ssl_object),
            OTHERNAMES_INTACT_KEY: peer_othernames_intact(ssl_object),
        }
        if client_cert_principal_under_issuer(verified, self._intake_subjects) is None:
            # A chain a trusted CA signed, carrying a subject nobody allow-listed under THAT CA — an
            # AUTHORIZATION failure, and deliberately distinct from the 401 above (deny-by-default).
            return self._charged(
                peer,
                HttpRequestError(
                    403,
                    "client certificate subject is not permitted",
                    kind="auth_subject_denied",
                ),
            )
        self._note_intake_success(peer)
        return None

    def _verified_issuer(self, ssl_object: Any) -> str:
        """The subject of the loaded CA that directly signed the peer's leaf, or ``""``.

        Read from the leaf's DER and the index alone. Never from ``getpeercert()["issuer"]``, which
        the issuing CA writes and OpenSSL matches to a CA loosely, folding case and whitespace; and
        never from ``get_verified_chain()``, which is empty on a resumed session. ``""`` matches no
        issuer, so anything that cannot be established is denied."""
        index = self._issuer_index
        if index is None:
            return ""
        try:
            leaf_der = ssl_object.getpeercert(binary_form=True)
            return index.issuer_of(leaf_der) if leaf_der else ""
        except Exception:
            # Deliberately broad, as the API shim's twin is: anything that stops the issuer being
            # established must DENY (a charged, audited 403), never escape into the generic
            # per-connection handler, which neither charges the attempt nor audits it.
            logger.warning(
                "HTTP source %s: could not establish a client certificate's issuer; denying",
                self._log_name,
                exc_info=True,
            )
            return ""

    def _presented_credential(self, head: HttpRequest) -> str | None:
        """The credential this request presents, or ``None``. Header names are already lower-cased."""
        if self._credential_header is None:
            return None
        value = head.headers.get(self._credential_header)
        if self.intake_auth == "api_key":
            return value
        if self.intake_auth == "bearer":
            scheme, _, token = (value or "").partition(" ")
            # OWS only, matching the header-value trim in the head parse; str.strip() would also
            # remove NBSP and NEL, so a bearer token and an API key would be trimmed differently.
            return token.strip(" \t") if scheme.lower() == "bearer" else None
        return None

    def _authorize_head(self, head: HttpRequest, peer_host: str | None) -> None:
        """Header-mode authentication, run **between the head and body reads** (the D6 split).

        Raises :class:`HttpRequestError`, so the refusal rides the shipped arm in ``_serve_one`` and
        is answered synchronously with nothing committed.
        """
        if self.intake_auth not in ("api_key", "bearer"):
            return
        if head.method in _HEALTH_PROBE_METHODS and self.intake_auth_health == "allow":
            return  # explicit opt-out for a load-balancer probe that cannot carry the credential
        peer = _peer_address(peer_host)
        forwarded = _client_readings(self._forwarded_client(head, peer))
        keys = (
            tuple(dict.fromkeys(_budget_key(reading) for reading in forwarded))
            if forwarded
            else (_peer_budget_key(peer_host, peer),)
        )
        try:
            self._authorize_credential(head, keys)
        except HttpRequestError as exc:
            # Recorded beside the socket peer, never instead of it, and as the address itself: the
            # key may be its /64, which says less about who sent the request. An ambiguous hop is
            # recorded as its whole-address reading, uvicorn's, unless that one was dropped.
            exc.forwarded_for = str(forwarded[0]) if forwarded else None
            raise

    def _forwarded_client(
        self, head: HttpRequest, peer: _HopAddress | None
    ) -> tuple[_HopAddress, ...]:
        """The client address a listed proxy forwarded, as :func:`_hop_readings` reads its hop, or
        empty to key on the socket peer.

        uvicorn's walk (BACKLOG #5525): the header counts only when the socket peer is a listed
        proxy; the hops are read right to left, a listed hop is skipped, and the first unlisted one
        is the client. That hop is the address the nearest listed proxy itself saw, so a client
        cannot choose it; everything left of it is the client's own text and is never read.
        uvicorn takes the left-most hop when every hop is listed, and this walk does not: it falls
        back to the socket peer then, as it does for a missing header or a hop that is not an
        address, so no budget is ever keyed on text a client wrote. An ambiguous hop is a listed
        hop only where every reading is listed, a phantom one included; otherwise it is the client,
        keyed as :func:`_client_readings` says, so no reading a client can steer onto a listed
        address moves the walk past it. A listed inner proxy whose hop is ambiguous is therefore
        skipped only where its other reading is listed too; otherwise every client behind it keys
        on its budget."""
        if not self._trusted_proxies or not head.forwarded_header:
            return ()
        if peer is None or not self._is_trusted_proxy(peer):
            return ()
        # Read hop by hop from the right with rfind, so each hop is scanned once and nothing left of
        # the client is touched, and stop after _MAX_FORWARDED_HOPS: a host inside a listed range
        # may pad the header with listed hops up to max_header_bytes, on the event loop.
        header = head.forwarded_header
        end = len(header)
        for _ in range(_MAX_FORWARDED_HOPS):
            start = header.rfind(",", 0, end)
            readings = _hop_readings(header[start + 1 : end])
            if not readings:
                return ()
            if not all(self._is_trusted_proxy(reading) for reading in readings):
                return readings
            if start < 0:
                return ()
            end = start
        return ()

    def _is_trusted_proxy(self, address: _HopAddress) -> bool:
        # Matched within the address's own family, so no spelling crosses over.
        return address in self._proxy_matcher

    def _authorize_credential(self, head: HttpRequest, peer: tuple[str, ...]) -> None:
        """The budget check and the credential comparison, keyed on each key in ``peer``."""
        limited = self._rate_limit_refusal(peer)
        if limited is not None:
            raise limited
        # A CREDENTIAL HEADER MUST APPEAR AT MOST ONCE (BACKLOG #2051). The head parse keeps the LAST
        # of two same-named lines, while a front end that authenticates the FIRST would have checked
        # a different credential from the one this listener accepts. Refused 400, as a repeated Host
        # is (BACKLOG #1972), and before any comparison. IDENTICAL values are refused too, because a
        # proxy may still split, merge or rewrite them. It sits AFTER the limiter and is charged and
        # audited as a failed attempt: the 400 tells a peer the header name was right, which the
        # 401 below does not, so that answer is held to the same budget as a guess. The reason
        # names neither the header nor its value. Under bearer it carries the RFC 6750 section 3.1
        # `invalid_request` challenge, the error code that RFC gives a repeated parameter.
        if self._credential_header_folded in head.repeated:
            raise self._charged(
                peer,
                HttpRequestError(
                    400,
                    "duplicate credential header",
                    kind="intake_auth_failed",
                    headers=(
                        {"WWW-Authenticate": 'Bearer error="invalid_request"'}
                        if self.intake_auth == "bearer"
                        else None
                    ),
                ),
            )
        if constant_time_match_any(self._presented_credential(head), self._intake_keys):
            self._note_intake_success(peer)
            return
        # Missing and wrong take the SAME path — one status, one body, no oracle telling an attacker
        # whether the header name was right.
        raise self._charged(
            peer,
            HttpRequestError(
                401,
                "intake authentication required",
                kind="intake_auth_failed",
                headers={"WWW-Authenticate": "Bearer"} if self.intake_auth == "bearer" else None,
            ),
        )

    async def _audit_intake_refusal(self, exc: HttpRequestError, peer_host: str | None) -> None:
        """Channels 1 and 2 of the three D6 audit channels (channel 3 is the ``connection_event``).

        **No credential material crosses this boundary** — not the value, not a prefix, not its
        length. The peer address and the mode are what an operator needs; the credential is what an
        attacker would need.
        """
        action = INTAKE_AUDIT_ACTIONS.get(exc.kind)
        if action is None:
            return
        # The reason is a fixed string at every call site, never request data, so it is safe to log.
        # It is what tells a repeated credential header apart from a wrong key (BACKLOG #2051). The
        # forwarded address is request data, but only ever an address `_hop_readings` parsed and
        # re-rendered, never the header's own text (BACKLOG #5525).
        logger.warning(
            "HTTP intake authentication refused: peer=%s forwarded_for=%s mode=%s outcome=%s "
            "reason=%s",
            peer_host or "unknown",
            exc.forwarded_for or "-",
            self.intake_auth,
            exc.kind,
            exc.reason,
        )
        sink = self.on_intake_audit
        if sink is None:
            return
        detail = _with_forwarded(f"mode={self.intake_auth}", exc)
        try:
            # The tamper-evident arm: connection_event is operator-disableable diagnostics, audit_log
            # is a hash chain they cannot silently switch off. Its client column stays the socket
            # peer; the forwarded address rides in the detail beside it.
            await sink(action, peer_host, detail)
        except Exception as sink_exc:  # fail-soft; an audit bug cannot drop an HTTP client
            logger.warning("HTTP intake audit emit failed: %s", safe_exc(sink_exc))

    async def _on_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        slot: tuple[str | None, int] | None = None,
    ) -> None:
        """Serve one connection. ``slot`` is the peer host and epoch of a slot
        `_handshake_accepted` already took for it, after its handshake, which this call then owns
        and releases."""
        assert self._handler is not None
        if slot is not None and self._admission.stopping:
            # The handshake `_handshake_accepted` ran finished after stop() began, so nothing will
            # wait for this connection: refuse it unread and unregistered, as
            # `MLLPSource._on_client` does. Nothing was read or written, so no close exchange is
            # owed: the transport is aborted rather than closed, so a peer that never answers
            # close_notify cannot keep the socket open for asyncio's 30 s shutdown default after
            # stop() has returned.
            self._admission.release(*slot)
            writer.transport.abort()
            return
        # A slot `_handshake_accepted` took is this call's from its first line, so the finally below
        # releases it however the call ends (BACKLOG #2479). Otherwise `epoch` is set by the admit,
        # and the finally releases exactly what it took.
        epoch: int | None = None
        if slot is not None:
            peer_host, epoch = slot
        else:
            peer_host = _peer_host(writer)
        # Register before anything else so stop() can always find + close this connection (H-2).
        # Dropped only as the last step of the finally below, after the close and the `closed`
        # event, so a stop() that begins while this call is still closing waits for it.
        task = asyncio.current_task()
        self._clients.add(writer)
        if task is not None:
            self._client_tasks.add(task)
        established = False
        failed = False
        # True from the start of a TLS handshake this listener runs until it succeeds; see
        # `MLLPSource._on_client` for why `wait_closed()` is skipped then (BACKLOG #1606).
        handshaking = False
        # False while a socket this listener upgrades is still plain TCP. Nothing is written to it
        # then: a TLS client cannot read a plaintext answer (BACKLOG #2479).
        answerable = not self._upgrade_tls
        try:
            # Kill Nagle on the accepted socket, as MLLPSource does. One request per connection
            # (build_response hardcodes Connection: close), so the 202 receipt is a single small
            # write with no unacked data outstanding — precisely the shape Nagle holds until the
            # peer's delayed-ACK timer fires. Best-effort and framing-neutral; see
            # _set_tcp_nodelay. Inside the try, so a fault here still releases a slot already held.
            _set_tcp_nodelay(writer)
            if slot is not None:
                refusal = None  # admitted before its handshake, by `_handshake_accepted`
            else:
                # vault BACKLOG #2606: stop, allowlist, global cap and per-host cap, decided in one
                # place for every socket listener (transports/admission.py). Refused before a
                # request byte, and, where this listener upgrades TLS itself, before any TLS byte
                # (BACKLOG #2479).
                refusal = self._admission.check(writer, peer_host, handshake=self._upgrade_tls)
            if refusal is not None:
                if refusal.kind is None:
                    return  # the listener is stopping: close unread, with no answer
                await self._emit_event(refusal.kind, peer_host=peer_host, reason=refusal.reason)
                # A socket still awaiting its upgrade gets no answer (see `answerable`), and a
                # handshake run only to refuse would be the work the pre-handshake refusal saves.
                if answerable:
                    status, body = (
                        (403, '{"error":"forbidden"}')
                        if refusal.kind == "peer_not_allowlisted"
                        else (503, '{"error":"at capacity"}')
                    )
                    await self._write_safely(writer, build_response(status, body))
                return  # refused (closed in the outer finally); no slot was taken
            if self._upgrade_tls:
                # The handshake runs inside an admitted slot (BACKLOG #2479), so a socket that never
                # sends a ClientHello is counted against both caps until the handshake bound ends
                # it, and the finally below gives the slot back however the handshake ends.
                # It also counts against the handshake budget until the handshake ends, however
                # it ends (vault BACKLOG #4888).
                epoch = self._admission.admit(peer_host)
                handshaking = True
                with self._admission.handshake(peer_host, epoch):
                    upgraded = await self._start_tls(reader, writer, peer_host)
                if not upgraded:
                    return  # never a session: no `established`, so no `closed` either
                handshaking = False
                answerable = True
                if self._admission.stopping:
                    # The handshake finished after stop() began: refuse it unread, aborted rather
                    # than closed, as the `slot` branch above says.
                    writer.transport.abort()
                    return
            # mTLS intake auth needs no request bytes at all, so it refuses here, before any read.
            # It needs the verified certificate, so it follows the handshake, inside the slot
            # admitted before it. Without TLS no slot is taken yet, and the refusal takes none.
            cert_refusal = self._authorize_peer_cert(writer, peer_host)
            if cert_refusal is not None:
                await self._emit_event(
                    cert_refusal.kind, peer_host=peer_host, reason=cert_refusal.reason
                )
                await self._audit_intake_refusal(cert_refusal, peer_host)
                await self._write_safely(
                    writer,
                    build_response(
                        cert_refusal.status,
                        json.dumps({"error": cert_refusal.reason}),
                        extra_headers=cert_refusal.headers,
                    ),
                )
                return  # pre-ingress refusal — nothing accepted, so nothing to count
            if epoch is None:
                epoch = self._admission.admit(peer_host)
            established = True
            await self._emit_event("established", peer_host=peer_host)
            failed = await self._serve_one(reader, writer, peer_host=peer_host)
        except OSError as exc:
            failed = True  # peer reset / write failure; nothing to do but drop the connection
            await self._emit_event("peer_reset", peer_host=peer_host, reason=safe_exc(exc))
        except Exception as exc:
            # Last-resort (ASVS 16.5.4): an unexpected error must not let the per-connection task die
            # silently or leak detail. Log redacted; try a 500; drop the connection.
            failed = True
            logger.error("HTTP connection failed unexpectedly: %s", safe_exc(exc))
            await self._emit_event("framing_error", peer_host=peer_host, reason=safe_exc(exc))
            if answerable:
                await self._write_safely(writer, build_response(500, '{"error":"internal error"}'))
        finally:
            try:
                if epoch is not None:
                    self._admission.release(peer_host, epoch)
                self._clients.discard(writer)
                writer.close()
                try:  # noqa: SIM105
                    # Bound the close (see stop()): an unbounded Proactor writer.wait_closed() would
                    # never let the per-client task finish, so stop()'s grace never sees it done
                    # (#55). Skipped for a socket whose TLS handshake never finished: see
                    # `handshaking`.
                    if not handshaking:
                        await asyncio.wait_for(writer.wait_closed(), timeout=_CLIENT_SHUTDOWN_GRACE)
                except (TimeoutError, OSError):
                    pass
                if established and not failed:
                    await self._emit_event("closed", peer_host=peer_host, reason="eof")
            finally:
                if task is not None:
                    self._client_tasks.discard(task)

    async def _serve_one(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, peer_host: str | None
    ) -> bool:
        """Read + answer exactly one request. Returns True if a pre-ingress failure occurred (so the
        outer ``closed`` event is suppressed — the failure already emitted its specific kind). Reading
        the whole request is bounded by ``receive_timeout`` (the slow-loris guard)."""
        assert self._handler is not None

        async def _read_authenticated() -> HttpRequest:
            """Head, then authentication, then body — the ADR 0154 D6 ordering.

            Header-mode auth sits between the two reads so an unauthenticated peer cannot make us
            buffer a body first: the credential is examined while the request is still just a head.
            """
            head = await _read_head(reader, max_header_bytes=self.max_header_bytes)
            self._authorize_head(head, peer_host)
            head.body = await _read_body(reader, head, max_body_bytes=self.max_body_bytes)
            return head

        # ASVS 2.4.1 / 15.2.2. The wait happens BEFORE any request byte is read, so the excess is
        # never parsed and never becomes a received message the count-and-log invariant would then
        # oblige us to account for. Nothing is dropped, refused or answered differently — the partner
        # is back-pressured by TCP while we decline to consume, and its request is served in full
        # once the debt clears. It sits OUTSIDE the receive_timeout budget below on purpose: a paced
        # partner must not be handed a 408 for a delay the engine itself imposed.
        if self._pacer is not None and (wait := self._pacer.deficit(now=time.monotonic())) > 0.0:
            await asyncio.sleep(wait)
        # BACKLOG #290 slice 2: the engine-wide intake pause, in the same place and for the same
        # reasons as the pacer wait above: before any request byte is read, outside receive_timeout.
        # A 503 answered unread was tried and dropped: closing a socket with the request still
        # unread resets it, and in this change's first Windows test run the peer lost the 503 to
        # that reset. Withholding the read loses nothing; the partner's own timeout and retry apply.
        # It withholds the GET/HEAD health probe too, since no byte says which method it is: a
        # paused listener reads as unresponsive to a probe, which is what it is for intake.
        if not await wait_for_intake(
            self.intake_gate, stopped=lambda: writer.is_closing() or reader.at_eof()
        ):
            return False  # stopping while paused: nothing was read, so there is nothing to answer

        try:
            # The whole head -> auth -> body sequence stays inside ONE receive_timeout budget; the
            # refusal RESPONSE is written below, outside it, so a 401 write cannot be cut off by the
            # slow-loris clock.
            if self.receive_timeout:
                request = await asyncio.wait_for(_read_authenticated(), self.receive_timeout)
            else:
                request = await _read_authenticated()
        except TimeoutError:
            # Slow-loris: the request didn't fully arrive within receive_timeout. Pre-ingress refuse.
            await self._emit_event("idle_timeout", peer_host=peer_host)
            await self._write_safely(writer, build_response(408, '{"error":"request timeout"}'))
            return True
        except HttpRequestError as exc:
            # Oversize / malformed / unsupported / unauthenticated — a synchronous 4xx + the ADR 0021
            # §7 pre-ingress connection_event (metadata only — never a body or field value). An
            # intake-auth refusal additionally writes its tamper-evident audit row here; it is a no-op
            # for every other kind.
            reason = _with_forwarded(exc.reason, exc)
            await self._emit_event(exc.kind, peer_host=peer_host, reason=reason)
            await self._audit_intake_refusal(exc, peer_host)
            await self._write_safely(
                writer,
                build_response(
                    exc.status, json.dumps({"error": exc.reason}), extra_headers=exc.headers
                ),
            )
            return True

        # Health probe: GET/HEAD answer a static, non-PHI 200 WITHOUT an ingress row (ADR 0023 D2).
        if request.method in _HEALTH_PROBE_METHODS:
            body = "" if request.method == "HEAD" else '{"status":"ok"}'
            await self._respond(writer, build_response(200, body))
            return False
        if request.method not in _BODY_METHODS:
            await self._write_safely(writer, build_response(405, '{"error":"method not allowed"}'))
            return False

        # ACK-on-receipt: hand the body to the pipeline handler, which commits it to the ingress stage
        # and returns the engine message_id. The 202 is the receipt-and-persistence signal (NOT a final
        # disposition) — a post-ingress routing/transform/delivery failure does NOT change this status
        # (it becomes the message's ERROR/dead-letter + AlertSink). count-and-log holds: the body is
        # persisted before the response is written — as a RECEIVED ingress row, or as an ERROR row when
        # the handler refuses it.
        receipt = await self._handler(request.body)
        # Charge one token AFTER the handler has recorded the body, so the debt is settled by the NEXT
        # request's pre-read wait and never by withholding this partner's answer. A GET/HEAD health
        # probe and a pre-ingress refusal charge nothing — they return above — which keeps a peer
        # that sends no message from spending the budget of one that does. A body the handler refuses
        # IS charged: it was read and recorded, which is the work the budget paces.
        if self._pacer is not None:
            self._pacer.charge(1, now=time.monotonic())

        message_id = receipt.message_id
        if receipt.refusal is not None:
            # The handler refused the body AFTER recording it with status ERROR, so that row is the
            # count-and-log record and only the answer changes here. A 202 would tell the caller its
            # body was accepted when it was not, and a reply_from caller would wait for a reply to a
            # message that never entered the pipeline. One branch answers both modes, so they cannot
            # drift (owner ruling 2026-09-26, BACKLOG #1960). The status says whether to re-send: the
            # owner ruling of 2026-09-30 answers a temporary refusal 503 with Retry-After and keeps a
            # permanent one at 422. Which refusals are temporary, the one 413 for over-size and the
            # ERROR row's id in the body are Manager decision d20261030T155119571-255c98 (BACKLOG #2105);
            # a strict-validation timeout that never began (BACKLOG #5078) joined the temporary class
            # later. A configuration refusal, at least the unusable codec name (BACKLOG #2431), is the
            # same 503 with no Retry-After, because it clears only when an operator acts (Manager
            # decision d20261104T003342588-cbb49e, BACKLOG #5102). Returns False:
            # this is a post-record refusal with no connection-event kind of its own, so the outer
            # ``closed`` still fires. The drain gets the receipt-sized budget in both modes: this is a
            # fixed few dozen bytes, never the partner-sized body reply_write_timeout exists for.
            status, headers = _refusal_status(receipt.refusal)
            # ``refused_message_id``, never ``message_id``: where this listener's own answer carries
            # ``message_id``, it names a committed message, so a refusal must not read as one. A
            # proxied reply_from 200 or 502 carries the partner's own bytes, which may hold its own.
            refused = json.dumps({"error": _NOT_ACCEPTED, "refused_message_id": message_id})
            await self._respond(
                writer,
                build_response(status, refused, extra_headers=headers),
                budget=_CLIENT_SHUTDOWN_GRACE,
            )
            return False

        if self.reply_from and self.sync_reply is not None:
            await self._respond_with_sync_reply(writer, message_id)
            return False

        accepted = {"status": "accepted", "message_id": message_id}
        await self._respond(writer, build_response(202, json.dumps(accepted)))
        return False

    async def _respond_with_sync_reply(self, writer: asyncio.StreamWriter, message_id: str) -> None:
        """Block on the captured downstream reply and answer with it (ADR 0154 D5).

        Reached only when ``reply_from`` is set **and** the runner injected a resolver, so an inbound
        without it never takes this path — that is what makes AC-8's "unchanged" true rather than
        aspirational. Reached only with a committed ``message_id``: a body the handler refused is
        answered ``503``, ``413`` or ``422`` by the caller before this is chosen.

        **The HTTP status is never a second disposition channel.** Whatever is returned here, the
        message stays committed and keeps flowing; its disposition is decided by the finalizer alone.
        A ``504`` does not cancel a delivery, and a ``200`` does not complete one.
        """
        resolver = self.sync_reply
        assert resolver is not None  # guarded by the caller, as _handler is above
        reply = await resolver(message_id)
        status, body, extra = self._reply_to_wire(reply, message_id)
        # No reply-derived bytes reach the log — only the outcome enum, the destination and timings.
        logger.debug(
            "sync reply %s: outcome=%s dest=%s seq=%s waited_ms=%s",
            message_id,
            reply.outcome.value,
            reply.destination,
            reply.response_seq,
            reply.waited_ms,
        )
        content_type = reply.content_type or "application/json"
        try:
            await self._respond(
                writer,
                build_response(status, body, content_type=content_type, extra_headers=extra),
            )
        except ValueError:
            # A partner Content-Type that fails the header guard must not take the turn down with
            # it: the body is still good, so fall back to our own type rather than 500 the caller.
            await self._respond(writer, build_response(status, body, extra_headers=extra))

    def _reply_to_wire(
        self, reply: InboundReply, message_id: str
    ) -> tuple[int, str, dict[str, str] | None]:
        """Map one resolved outcome onto ``(status, body, extra_headers)`` — ADR 0154 D5's table.

        Every row of that table maps to exactly one outcome and every outcome to exactly one row.
        Refusal and timeout bodies are **fixed, non-PHI JSON**; only ``reply`` and ``rejected`` carry
        partner bytes, and those are exactly the two the caller asked to be proxied.
        """
        outcome = reply.outcome
        if outcome is ReplyOutcome.REPLY:
            return 200, reply.body or "", None
        if outcome is ReplyOutcome.REJECTED:
            # The partner's own negative answer is the most useful thing we can return.
            return 502, reply.body or "", None
        if outcome is ReplyOutcome.EMPTY:
            return (204, "", None) if self.reply_on_empty == "204" else (200, "", None)
        if outcome is ReplyOutcome.TIMEOUT:
            payload = json.dumps({"status": "timeout", "message_id": message_id})
            return (504 if self.reply_on_timeout == "504" else 202), payload, None
        if outcome is ReplyOutcome.NO_ROUTE:
            # Answered IMMEDIATELY with the timeout status rather than after the full budget: the
            # message is already terminal, so waiting would burn the caller's patience for nothing.
            payload = json.dumps({"status": "no_route", "message_id": message_id})
            return (504 if self.reply_on_timeout == "504" else 202), payload, None
        if outcome is ReplyOutcome.SHUTTING_DOWN:
            payload = json.dumps({"status": "shutting_down", "message_id": message_id})
            # Never a 504 on a demotion: the new leader is about to deliver this message, so claiming
            # the partner timed out would be a lie about a message that is still in flight.
            return 503, payload, {"Retry-After": "5"}
        if outcome is ReplyOutcome.PURGED:
            payload = json.dumps({"status": "reply_purged", "message_id": message_id})
            return 502, payload, None
        if outcome is ReplyOutcome.DEGRADED:
            payload = json.dumps({"status": "degraded", "message_id": message_id})
            return (504 if self.reply_on_timeout == "504" else 202), payload, None
        payload = json.dumps({"status": "delivery_failed", "message_id": message_id})
        return 502, payload, None

    async def _respond(
        self, writer: asyncio.StreamWriter, data: bytes, *, budget: float | None = None
    ) -> None:
        """Write the success-path response, bounding the drain.

        ``budget`` overrides :meth:`_drain_budget` for a response whose size does not depend on the
        mode, such as the fixed-size answer to a refused body.

        The drain was unbounded: a peer that stops reading held the connection — and its
        ``max_connections`` slot, since the admitted slot spans all of ``_serve_one`` — for as long as it
        liked, with no clock on it (``receive_timeout`` bounds the *read*, not the write). The refuse
        path already bounds its drain the same way in ``_write_safely``; only the success path did not.

        A timeout raises, and is handled by ``_on_client``'s existing ``OSError`` arm (``TimeoutError``
        subclasses ``OSError``), which emits ``peer_reset`` and drops the connection. Deliberately not a
        new ``connection_event`` kind: the vocabulary is asserted in CI against ``docs/PHI.md`` §7 and
        ``CONNECTION_EVENT_KINDS`` as an exact set, so minting one is a three-file change, and
        "the peer stopped reading" is what ``peer_reset`` already means to an operator.

        The message is unaffected either way — it was recorded before this write (ACK-on-receipt),
        so a lost answer costs the sender a retry, never a message. For a ``202`` that record is the
        committed ingress row; for the answer to a refused body it is the ``ERROR`` row.
        """
        writer.write(data)
        await asyncio.wait_for(writer.drain(), self._drain_budget() if budget is None else budget)

    def _drain_budget(self) -> float:
        """Seconds allowed to drain a response to the caller.

        ``_CLIENT_SHUTDOWN_GRACE`` for the shipped ``202`` path, which writes a few dozen bytes and
        was bounded by that constant in increment A. A ``reply_from`` inbound instead uses its own
        ``reply_write_timeout``, because it now carries a **partner-sized** body to a possibly slow
        reader and a receipt-sized budget would truncate a legitimate large reply.

        The two are not interchangeable in the other direction either: ``reply_write_timeout``
        defaults to 30 s against a 5 s shutdown grace, so ``stop()`` clamps this to its own
        sub-budget rather than letting one drain outlive the entire teardown by 6x.
        """
        if self.reply_from:
            # reply_seconds guarantees seconds above zero, so no falsy fallback is needed.
            return self.reply_write_timeout
        return _CLIENT_SHUTDOWN_GRACE

    async def _write_safely(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        """Best-effort error/refuse response — never raise out of the refuse/close path (the socket may
        already be gone). Drains (bounded) so the 4xx actually reaches the peer before the connection is
        closed in the caller's finally, but a drain failure on an already-reset socket is swallowed."""
        try:
            writer.write(data)
            await asyncio.wait_for(writer.drain(), _CLIENT_SHUTDOWN_GRACE)
        except (TimeoutError, OSError):
            pass


register_source(ConnectorType.HTTP, HttpSource)
