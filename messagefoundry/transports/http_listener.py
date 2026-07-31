# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Inbound HTTP/1.1 listen source — a connector-owned SOAP/REST web-service receiver (ADR 0023).

A partner ``POST``s a body (JSON / XML / text / HL7-over-HTTP) and the listener decodes it, hands it
to the pipeline's :class:`~messagefoundry.transports.base.InboundHandler` exactly as
:class:`~messagefoundry.transports.mllp.MLLPSource` hands a de-framed MLLP message, and returns a
**``202 Accepted`` respond-with-receipt** the instant the raw body is durably committed to the
ingress stage — mirroring MLLP's AA-on-receipt (ACK-on-receipt, ADR 0001). A post-ingress
routing/transform/delivery failure happens *after* the ``202`` and is **not** reflected in the HTTP
status — it surfaces only as the message's ``ERROR``/dead-letter disposition + the AlertSink, exactly
as a post-ACK MLLP failure does.

**Why this lives in ``transports/`` and not ``api/``.** The one-way dependency rule (CLAUDE.md §2/§4)
forbids ``transports/`` from importing ``api/``. The engine's FastAPI app stays the admin/RBAC surface;
message intake is a registry connector that owns its own bound ``asyncio`` socket. So this is a
**stdlib-only** HTTP/1.1 request reader over ``asyncio.start_server`` — **no new web-framework
dependency** (FastAPI/uvicorn are an ``api/`` concern).

It is a faithful ``MLLPSource`` sibling: it inherits the per-connection IP allowlist, per-connection
inbound TLS, the runner's exposed-gate (``check_http_tls_exposure``), ADR 0031 fault isolation, and the
ADR 0021 ``connection_event`` log (**on by default** — ``[diagnostics].connection_events`` is ``True``
and the per-connection flag inherits it; see ``docs/PHI.md`` §7). The DoS guards have HTTP analogs: ``max_connections``
(connection-flood), ``receive_timeout`` (slow-loris — bounds the time to read the request line +
headers + body), and ``max_body_bytes`` (the ``MLLPDecoder`` frame cap's HTTP twin — a
``Content-Length`` / read ceiling).

**First slice (ADR 0023 D3).** Only the cheap, correct ``202``-respond-with-receipt path is built. A
synchronous downstream-reply (the SOAP-envelope ``block-on-captured-downstream-reply`` seam) is a
defined ADR 0013 follow-on and is **not** built here. ``GET``/``HEAD`` are answered with a static,
non-PHI health response **without** an ingress row; any other method is ``405``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import ssl
from collections.abc import Awaitable, Callable, Mapping

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.redaction import safe_exc
from messagefoundry.transports.base import (
    InboundHandler,
    SourceConnector,
    peer_ip_allowed,
    register_source,
)
from messagefoundry.transports.mllp import (
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_RECEIVE_TIMEOUT,
    _mllp_ssl_context,
    _peer_host,
    _set_tcp_nodelay,
)

__all__ = [
    "DEFAULT_MAX_BODY_BYTES",
    "DEFAULT_MAX_HEADER_BYTES",
    "HttpRequest",
    "HttpRequestError",
    "HttpSource",
]

logger = logging.getLogger(__name__)

# Resource caps (DoS guards), HTTP analogs of the MLLP frame/connection/idle caps. All overridable per
# connection via Http() settings; a falsy value (None/0) disables a cap explicitly where noted.
DEFAULT_MAX_BODY_BYTES = (
    16 * 1024 * 1024
)  # 16 MiB — matches the MLLP frame cap + the engine ceiling
DEFAULT_MAX_HEADER_BYTES = (
    64 * 1024
)  # cap the request line + headers (a header-flood / slow-loris guard)
_READ_CHUNK = 65536  # body read granularity

# On stop()/reload, established clients are closed and their handlers given this long to finish an
# in-flight commit before the connection tasks are cancelled (mirrors MLLPSource; bounds shutdown).
_CLIENT_SHUTDOWN_GRACE = 5.0


class HttpRequestError(Exception):
    """A request could not be parsed / exceeded a cap **before** an ingress row was written.

    Carries the HTTP ``status`` to return synchronously (the HTTP twin of MLLP's synchronous AR/AE
    NAK) and a connection-event ``kind`` (ADR 0021 §7, metadata-only) for the pre-ingress failure.
    """

    def __init__(self, status: int, reason: str, *, kind: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.kind = kind


class HttpRequest:
    """One parsed inbound HTTP request — method/path/headers + the body bytes.

    Treated as **untrusted data** (CLAUDE.md §8): the method/path/headers are surfaced as routing
    metadata (ADR 0004 §4), never executed; the body is handed verbatim to the pipeline handler.
    """

    __slots__ = ("method", "target", "headers", "body")

    def __init__(self, method: str, target: str, headers: dict[str, str], body: bytes) -> None:
        self.method = method
        self.target = target
        self.headers = headers
        self.body = body


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

    **Every header name and value, including ``content_type``, is validated here rather than at the
    call site.** This function joins the header block with ``\\r\\n``, so it *is* the chokepoint: a
    value carrying CR or LF is a header-injection primitive, and validating in the callers would mean
    each future consumer has to remember. Today every caller passes a literal, so this guards against
    a future one — notably the captured-reply path, which echoes a partner's ``Content-Type``."""
    payload = body.encode("utf-8")
    headers = [
        _status_line(status),
        _validated_header("Content-Type", content_type),
        f"Content-Length: {len(payload)}",
    ]
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
    ``max_connections × max_body_bytes`` of resident heap — transiently about twice that on the
    no-``Content-Length`` path, where :func:`_read_to_eof` accumulates a chunk list and then joins it
    — before a single credential byte was examined. The connection cap cannot shed that load either,
    because it is consulted earlier still, in ``_on_client``. Keep any new pre-body refusal here.

    Raises :class:`HttpRequestError` (carrying the status + connection-event kind) on an unbounded
    header read, a malformed request line, or ambiguous framing, so the caller can answer
    synchronously **before** any ingress row is written."""
    # Request line + headers, bounded by max_header_bytes (so a peer can't stream headers forever).
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as exc:
        raise HttpRequestError(400, "incomplete request head", kind="framing_error") from exc
    except asyncio.LimitOverrunError as exc:
        # StreamReader's own buffer limit tripped before the terminator — treat as an oversize head.
        raise HttpRequestError(413, "request head exceeds cap", kind="frame_oversize") from exc
    if len(head) > max_header_bytes:
        raise HttpRequestError(413, "request head exceeds cap", kind="frame_oversize")

    try:
        text = head.decode("iso-8859-1")  # HTTP/1.1 header octets are latin-1 (RFC 7230)
        lines = text.split("\r\n")
        request_line = lines[0]
        method, target, version = request_line.split(" ", 2)
    except (UnicodeDecodeError, ValueError) as exc:
        raise HttpRequestError(400, "malformed request line", kind="framing_error") from exc
    if not version.startswith("HTTP/"):
        raise HttpRequestError(400, "malformed request line", kind="framing_error")

    headers: dict[str, str] = {}
    header_counts: dict[str, int] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep:
            raise HttpRequestError(400, "malformed header line", kind="framing_error")
        key = name.strip().lower()
        header_counts[key] = header_counts.get(key, 0) + 1
        headers[key] = value.strip()

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

    method = method.upper()
    return HttpRequest(method, target, headers, b"")


async def _read_body(
    reader: asyncio.StreamReader,
    head: HttpRequest,
    *,
    max_body_bytes: int | None,
) -> bytes:
    """Read the body belonging to an already-parsed ``head``, applying the body cap.

    Split out of :func:`_read_request` so authentication can run between the two halves (see
    :func:`_read_head`). The ordering inside is load-bearing and is preserved exactly as it shipped:
    the GET/HEAD short-circuit runs **before** the chunked refusal, so a ``GET`` carrying
    ``Transfer-Encoding: chunked`` is accepted with an empty body rather than refused. Hoisting that
    refusal would read as hardening and would in fact be a silent behaviour change."""
    # Only methods that carry a body read one. GET/HEAD are health probes (no body, no ingress).
    if head.method in ("GET", "HEAD"):
        return b""

    body = b""
    cl_raw = head.headers.get("content-length")
    if head.headers.get("transfer-encoding", "").lower() == "chunked":
        # Chunked intake is not part of the first slice — a partner that streams must use Content-Length.
        raise HttpRequestError(
            400, "chunked transfer-encoding is not supported", kind="framing_error"
        )
    if cl_raw is not None:
        try:
            content_length = int(cl_raw)
            if content_length < 0:
                raise ValueError
        except ValueError as exc:
            raise HttpRequestError(400, "invalid Content-Length", kind="framing_error") from exc
        if max_body_bytes is not None and content_length > max_body_bytes:
            # Refuse on the DECLARED size before reading a single body byte (don't buffer to find out).
            raise HttpRequestError(413, "body exceeds cap", kind="frame_oversize")
        body = await _read_exactly(reader, content_length)
    elif head.method in ("POST", "PUT", "PATCH"):
        # No Content-Length and not chunked: read to EOF (Connection: close), still bounded by the cap.
        body = await _read_to_eof(reader, max_body_bytes)
    return body


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
    """Read exactly ``n`` body bytes; tolerate a short/early close (return what arrived)."""
    if n == 0:
        return b""
    try:
        return await reader.readexactly(n)
    except asyncio.IncompleteReadError as exc:
        return exc.partial


async def _read_to_eof(reader: asyncio.StreamReader, cap: int | None) -> bytes:
    """Read body bytes to EOF, enforcing ``cap`` (None disables it). Refuses past the cap rather than
    buffering an unbounded body (the OOM guard the MLLPDecoder cap provides for framed transports)."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await reader.read(_READ_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if cap is not None and total > cap:
            raise HttpRequestError(413, "body exceeds cap", kind="frame_oversize")
        chunks.append(chunk)
    return b"".join(chunks)


# The runner injects an HTTP receipt handler that commits the body to ingress and returns the engine
# message_id (the first-slice receipt), or returns None when the body was NOT committed (a post-decode
# engine guard, e.g. the ingress size ceiling). Distinct from the bytes->str|None InboundHandler so the
# 202 can carry the message_id (ADR 0023 AC-2) without changing the MLLP/TCP reply contract.
HttpReceiptHandler = Callable[[bytes], Awaitable[str | None]]


class HttpSource(SourceConnector):
    """Listen for inbound HTTP/1.1 requests, commit each POSTed body to the ingress stage via the
    pipeline handler, and return a ``202`` respond-with-receipt once it is durably committed (ADR 0023).

    A faithful :class:`~messagefoundry.transports.mllp.MLLPSource` sibling: same bind/stop lifecycle,
    per-connection IP allowlist, inbound TLS, and on-by-default ``connection_event`` plumbing."""

    def __init__(self, config: Source) -> None:
        s = config.settings
        # The bind interface is injected from the service's [inbound].bind_host (authors never set a
        # host on an inbound). Fall back to loopback for a missing/None value — never bind all
        # interfaces (0.0.0.0) by accident. The runner's exposed-gate refuses a non-loopback bind
        # without TLS (check_http_tls_exposure). See docs/CONNECTIONS.md.
        self.host: str = s.get("host") or "127.0.0.1"
        self.port: int = int(s["port"])
        # Caps below: key absent → secure default; present-but-falsy (None/0) → disabled where allowed.
        mc = s.get("max_connections", DEFAULT_MAX_CONNECTIONS)
        self.max_connections: int | None = int(mc) if mc else None
        rt = s.get("receive_timeout", DEFAULT_RECEIVE_TIMEOUT)
        self.receive_timeout: float | None = float(rt) if rt else None
        mb = s.get("max_body_bytes", DEFAULT_MAX_BODY_BYTES)
        self.max_body_bytes: int | None = int(mb) if mb else None
        mh = s.get("max_header_bytes", DEFAULT_MAX_HEADER_BYTES)
        self.max_header_bytes: int = int(mh) if mh else DEFAULT_MAX_HEADER_BYTES
        # Per-connection peer-IP allowlist (Tier 4): refuse a non-listed peer at accept (fail-closed).
        # Absent/empty = no restriction. Mirrors MLLPSource.
        sa = s.get("source_ip_allowlist")
        self.source_ip_allowlist: list[str] | None = [str(x) for x in sa] if sa else None
        # Per-connection inbound TLS (present a server cert; opt-in mTLS via tls_ca_file), built once at
        # construction so a bad cert/key fails at build. None when tls is off → plaintext, byte-identical.
        self._ssl: ssl.SSLContext | None = _mllp_ssl_context(s, server=True)
        self._server: asyncio.Server | None = None
        self._handler: InboundHandler | None = None
        self._active = 0
        # Live client writers + handler tasks so stop()/reload can actively close established
        # connections and bound the wait (mirrors MLLPSource, review H-2 / #55).
        self._clients: set[asyncio.StreamWriter] = set()
        self._client_tasks: set[asyncio.Task[None]] = set()

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        # leader_gate is ignored: a listen source runs on every node (each binds its own endpoint), so
        # there is no shared-resource double-read to gate. Accepted only so the runner's call is uniform.
        self._handler = handler
        self._server = await asyncio.start_server(
            self._on_client, self.host, self.port, ssl=self._ssl
        )

    @property
    def sockport(self) -> int:
        """The actual bound port (useful when configured with port 0 in tests)."""
        assert self._server is not None
        port: int = self._server.sockets[0].getsockname()[1]
        return port

    async def stop(self) -> None:
        # Stop accepting NEW connections (this alone does not close established ones).
        if self._server is not None:
            self._server.close()
        # Close established clients BEFORE awaiting the server (server.wait_closed() hangs on py3.12.1+
        # waiting for in-flight handlers of a peer holding its connection open). A request mid-handler
        # still finishes its commit (the body is durably stored before the 202, so at-least-once holds).
        # Then await the connection tasks with a bounded grace and cancel any stragglers (review H-2).
        for writer in list(self._clients):
            writer.close()
        pending = [task for task in self._client_tasks if not task.done()]
        if pending:
            _done, still_running = await asyncio.wait(pending, timeout=_CLIENT_SHUTDOWN_GRACE)
            for task in still_running:
                task.cancel()
            if still_running:
                await asyncio.gather(*still_running, return_exceptions=True)
        self._clients.clear()
        self._client_tasks.clear()
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

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        assert self._handler is not None
        # Register before anything else so stop() can always find + close this connection (H-2).
        task = asyncio.current_task()
        self._clients.add(writer)
        if task is not None:
            self._client_tasks.add(task)
        # Kill Nagle on the accepted socket, as MLLPSource does. One request per connection
        # (build_response hardcodes Connection: close), so the 202 receipt is a single small write with
        # no unacked data outstanding — precisely the shape Nagle holds until the peer's delayed-ACK
        # timer fires. Best-effort and framing-neutral; see _set_tcp_nodelay.
        _set_tcp_nodelay(writer)
        peer_host = _peer_host(writer)
        established = False
        failed = False
        try:
            if self.source_ip_allowlist is not None:
                peer = writer.get_extra_info("peername")
                if not peer_ip_allowed(peer, self.source_ip_allowlist):
                    logger.warning(
                        "HTTP connection from %s refused: not in source_ip_allowlist", peer
                    )
                    await self._emit_event("peer_not_allowlisted", peer_host=peer_host)
                    await self._write_safely(writer, build_response(403, '{"error":"forbidden"}'))
                    return  # not allowlisted — refuse (closed in the outer finally; _active untouched)
            if self.max_connections is not None and self._active >= self.max_connections:
                await self._emit_event("at_capacity", peer_host=peer_host)
                await self._write_safely(writer, build_response(503, '{"error":"at capacity"}'))
                return  # at capacity — refuse the new client
            self._active += 1
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
            await self._write_safely(writer, build_response(500, '{"error":"internal error"}'))
        finally:
            if established:
                self._active -= 1
            self._clients.discard(writer)
            if task is not None:
                self._client_tasks.discard(task)
            writer.close()
            try:  # noqa: SIM105
                # Bound the close (see stop()): an unbounded Proactor writer.wait_closed() would never
                # let the per-client task finish, so stop()'s grace never sees it done (#55).
                await asyncio.wait_for(writer.wait_closed(), timeout=_CLIENT_SHUTDOWN_GRACE)
            except (TimeoutError, OSError):
                pass
            if established and not failed:
                await self._emit_event("closed", peer_host=peer_host, reason="eof")

    async def _serve_one(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, peer_host: str | None
    ) -> bool:
        """Read + answer exactly one request. Returns True if a pre-ingress failure occurred (so the
        outer ``closed`` event is suppressed — the failure already emitted its specific kind). Reading
        the whole request is bounded by ``receive_timeout`` (the slow-loris guard)."""
        assert self._handler is not None
        try:
            if self.receive_timeout:
                request = await asyncio.wait_for(
                    _read_request(
                        reader,
                        max_header_bytes=self.max_header_bytes,
                        max_body_bytes=self.max_body_bytes,
                    ),
                    self.receive_timeout,
                )
            else:
                request = await _read_request(
                    reader,
                    max_header_bytes=self.max_header_bytes,
                    max_body_bytes=self.max_body_bytes,
                )
        except TimeoutError:
            # Slow-loris: the request didn't fully arrive within receive_timeout. Pre-ingress refuse.
            await self._emit_event("idle_timeout", peer_host=peer_host)
            await self._write_safely(writer, build_response(408, '{"error":"request timeout"}'))
            return True
        except HttpRequestError as exc:
            # Oversize / malformed / unsupported — a synchronous 4xx + the ADR 0021 §7 pre-ingress
            # connection_event (metadata only — never a body or field value).
            await self._emit_event(exc.kind, peer_host=peer_host, reason=exc.reason)
            await self._write_safely(
                writer, build_response(exc.status, json.dumps({"error": exc.reason}))
            )
            return True

        # Health probe: GET/HEAD answer a static, non-PHI 200 WITHOUT an ingress row (ADR 0023 D2).
        if request.method in ("GET", "HEAD"):
            body = "" if request.method == "HEAD" else '{"status":"ok"}'
            await self._respond(writer, build_response(200, body))
            return False
        if request.method not in ("POST", "PUT", "PATCH"):
            await self._write_safely(writer, build_response(405, '{"error":"method not allowed"}'))
            return False

        # ACK-on-receipt: hand the body to the pipeline handler, which commits it to the ingress stage
        # and returns the engine message_id. The 202 is the receipt-and-persistence signal (NOT a final
        # disposition) — a post-ingress routing/transform/delivery failure does NOT change this status
        # (it becomes the message's ERROR/dead-letter + AlertSink). count-and-log holds: the body is
        # persisted before the response is written.
        message_id = await self._handler(request.body)
        receipt = {"status": "accepted"}
        if message_id is not None:
            receipt["message_id"] = message_id
        await self._respond(writer, build_response(202, json.dumps(receipt)))
        return False

    async def _respond(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        """Write the success-path response, bounding the drain.

        The drain was unbounded: a peer that stops reading held the connection — and its
        ``max_connections`` slot, since ``_active`` spans all of ``_serve_one`` — for as long as it
        liked, with no clock on it (``receive_timeout`` bounds the *read*, not the write). The refuse
        path already bounds its drain the same way in ``_write_safely``; only the success path did not.

        A timeout raises, and is handled by ``_on_client``'s existing ``OSError`` arm (``TimeoutError``
        subclasses ``OSError``), which emits ``peer_reset`` and drops the connection. Deliberately not a
        new ``connection_event`` kind: the vocabulary is asserted in CI against ``docs/PHI.md`` §7 and
        the console's filter tuple as an exact set, so minting one is a three-file change, and
        "the peer stopped reading" is what ``peer_reset`` already means to an operator.

        The message is unaffected either way — it was durably committed to ingress before this write
        (ACK-on-receipt), so a lost 202 costs the sender a retry, never a message.
        """
        writer.write(data)
        await asyncio.wait_for(writer.drain(), _CLIENT_SHUTDOWN_GRACE)

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
