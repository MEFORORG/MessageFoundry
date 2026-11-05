# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A loopback HTTP server shared by the four HTTP-family sinks (REST, SOAP, FHIR, DICOMweb).

Sink discovery keys on ONE ``KIND`` per module, so each kind has its own tiny module
(``rest.py``, ``soap.py``, ``fhir.py``, ``dicomweb.py``) that subclasses :class:`HttpSink` and
sets its kind. This helper is ``_``-prefixed, so discovery skips it.

Each request is recorded as a :class:`~harness.sinks.Record`: the body as ``payload``, and in
``meta`` the ``method``, ``path`` (the request target as sent), ``content-type``, the ``status``
the sink answered, the ``peer``, and every request header as ``header:<lower-cased name>``. The
values of at least the headers in :data:`REDACTED_HEADERS` are recorded as ``<redacted>``. That
is not every place a credential can travel: a SOAP ``ws_security`` password or a ``body_secrets``
value is in the BODY, and ``dynamic_headers`` can put one under any name, so point a sink only at
an outbound carrying test credentials. No request is logged: the stdlib server's per-request line
is silenced, and a handler error is logged at DEBUG without the request. The one other log line
is the self-test's refusal, below, at ERROR; it names cases and headers, never a request.

``status`` picks the answer, and can be changed between runs: a 2xx is a delivery, a 5xx drives
the outbound's retry and then dead-letter path, a 4xx its permanent-rejection path. The sink reads
only a ``Content-Length`` framed body, and records a request it refuses with an empty payload and a
``refused`` reason: ``413`` over the engine's per-message cap, ``400`` for a malformed length or
any ``Transfer-Encoding``, ``411`` for a body method with no length, and ``408`` when the declared
body does not arrive within :data:`READ_TIMEOUT_SECONDS`. For the first three it answers, then
discards what the peer still sends, up to a bound, so a peer that writes its whole body before
reading sees the refusal rather than a reset.

Every answer carries :data:`BASELINE_RESPONSE_HEADERS`: ``nosniff``, a framing and ``<base>``
policy, and the rest of the engine listener's baseline (ASVS 3.4.4 and 3.4.6, and the ``base-uri``
part of 3.4.3; BACKLOG #1120).
That includes the answers the stdlib handler writes before the sink's own code runs, such as its
``400`` for a malformed request line and its ``501`` for a method the sink does not serve. The
handler's ``end_headers`` adds them, and the stdlib closes every header block through that one
method. Nothing is answered in HTTP/0.9 form, which has no status line and no header block; the
comment on the handler's ``request_version`` says which answers the stdlib writes that way and
how the sink avoids it. No answer carries a ``Server`` line: the stdlib's names the Python patch
level, and the engine listener sends none.

The stdlib's own error answers are ``text/plain``, not its default HTML page. The comment on the
handler's ``error_content_type`` names the paths that were read.

**The sink refuses to start on a Python whose answers it cannot floor** (BACKLOG #1121; owner
ruling R1 of the vault's ``ASVS-OWNER-RULINGS-2026-10-23-BATCH340``). The project requires Python
``>=3.14`` and does not pin a patch release, and the stdlib handler changed which answers it writes
bare between patch releases. So :meth:`HttpSink.start` first runs :func:`self_test`, which serves
each request in :data:`SELF_TEST_CASES` on a throwaway loopback server built from this module's
handler, on the running Python, and reads the bytes back. If any final answer lacks a
:data:`BASELINE_RESPONSE_HEADERS` line, carries one twice, names no ``frame-ancestors 'none'``
policy, or carries a ``Server`` or HSTS line, or if an answer cannot be read at all, it logs at
ERROR and raises :class:`SinkSelfTestError` before the sink's own port is bound. An answer
family a later Python adds that the table does not name stays uncovered; R1 accepts that as a
residual.
"""

from __future__ import annotations

import http.client
import logging
import re
import socket
import socketserver
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

from harness.sinks import LOOPBACK, Record, Sink
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

__all__ = [
    "BASELINE_RESPONSE_HEADERS",
    "LOOPBACK",
    "REDACTED",
    "REDACTED_HEADERS",
    "SELF_TEST_CASES",
    "HttpSink",
    "SelfTestCase",
    "SinkSelfTestError",
    "check_status",
    "self_test",
]

_log = logging.getLogger(__name__)

#: Headers whose VALUES are credentials. Their presence is recorded; their value never is.
REDACTED_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "x-api-key"})
REDACTED = "<redacted>"

#: The browser-safety baseline on every answer. The values are the engine HTTP listener's own
#: (``_BASELINE_RESPONSE_HEADERS`` in ``messagefoundry/transports/http_listener.py``).
#:
#: This is a COPY, and the dependency rule forces it: the harness is a client and may not import
#: ``messagefoundry.transports`` (``tests/test_dependency_boundaries.py``). The API's header floor is
#: not the source either, since importing it would pull Starlette into the harness process.
#: ``tests/test_harness_http_headers.py`` imports both constants and asserts they are equal, which is
#: the one place a divergence turns red. Do not "fix" the copy by importing across the boundary.
#:
#: ``Strict-Transport-Security`` is absent on purpose: the sink is cleartext on loopback.
BASELINE_RESPONSE_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    ("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'"),
)

#: How long one socket read may wait, so a peer that declares more than it sends cannot hold a
#: handler thread (or a stop) open.
READ_TIMEOUT_SECONDS = 5.0

#: The most a refused over-cap body is read and discarded for, so its sender reads the 413.
_DRAIN_LIMIT = 2 * DEFAULT_MAX_MESSAGE_BYTES

_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})

#: More digits than any length the sink would read (the cap is 8 digits); refused, never parsed.
_MAX_LENGTH_DIGITS = 18


def check_status(status: int) -> None:
    """Refuse a status a peer cannot end a request with (a 1xx is interim) or that is not HTTP."""
    if not 200 <= status <= 599:
        raise ValueError(f"status must be a final HTTP status (200-599), got {status}")


class SinkSelfTestError(OSError):
    """The sink's answers on this Python lack the baseline headers, so the sink will not start.

    An ``OSError``, as a port that will not bind is: a setup failure, not a verdict on the engine,
    so the harness CLI's ``--scenario`` reports it as SETUP (exit 2), not FAIL."""


@dataclass(frozen=True)
class SelfTestCase:
    """One answer family :func:`self_test` drives, and ``tests/test_harness_http_headers.py`` too.

    ``statuses`` are the header blocks the suite expects, interim ones included. The self-test
    does not refuse on a status: it checks the headers on whatever final answer comes back.
    """

    name: str
    request: bytes
    statuses: tuple[int, ...]
    #: The status the sink is configured to answer with.
    sink_status: int = 200
    #: The request declares a body it never finishes, and the peer keeps its side open: the 408.
    stalls: bool = False


#: The longest request line the stdlib reads: a literal in http/server.py's handle_one_request,
#: with no name to read it from. A release that raises it reads the 414 case, a two-word line
#: ended by the half-close, as an HTTP/0.9 GET instead of answering the 414.
_REQUEST_LINE_LIMIT = 65536
#: The longest header line: http.client's private _MAXLINE, which parse_headers reads.
_HEADER_LINE_LIMIT: int = getattr(http.client, "_MAXLINE", 65536)
#: The most headers parse_headers reads: http.client's private _MAXHEADERS.
_HEADER_COUNT_LIMIT: int = getattr(http.client, "_MAXHEADERS", 100)
_GET_LINE = b"GET /x HTTP/1.1\r\n"
_POST = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}"

#: Every answer family the sink writes that the header suite pins: the sink's own answers and
#: refusals, and the answers the stdlib handler writes before the sink's code runs. Each request
#: ends where the stdlib stops reading on Python 3.14, because the stdlib closes without draining
#: and a close with input still unread can reset the connection and discard the answer: after the
#: request line when it answers from that line alone, after the blank line when it reads headers
#: first. Which of the HTTP/0.9 cases a given stdlib answers bare depends on the patch level.
SELF_TEST_CASES: tuple[SelfTestCase, ...] = (
    SelfTestCase("200", _POST, (200,)),
    SelfTestCase("configured-400", _POST, (400,), sink_status=400),
    SelfTestCase("configured-503", _POST, (503,), sink_status=503),
    SelfTestCase("get", b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n", (200,)),
    SelfTestCase("head", b"HEAD /x HTTP/1.1\r\nHost: x\r\n\r\n", (200,)),
    # --- the sink's own refusals ---------------------------------------------------------------
    SelfTestCase(
        "413-over-cap",
        b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999\r\n\r\n",
        (413,),
    ),
    SelfTestCase("411-no-length", b"POST /x HTTP/1.1\r\nHost: x\r\n\r\n", (411,)),
    SelfTestCase(
        "400-transfer-encoding",
        b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
        (400,),
    ),
    SelfTestCase(
        "408-stalled-body",
        b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nonly ten b",
        (408,),
        stalls=True,
    ),
    # --- answers the stdlib handler writes itself, before the sink's handler runs --------------
    SelfTestCase("stdlib-400-malformed", b"NOT A REQUEST\r\n", (400,)),
    SelfTestCase("stdlib-501-method", b"BREW /x HTTP/1.1\r\nHost: x\r\n\r\n", (501,)),
    SelfTestCase("stdlib-505-version", b"GET /x HTTP/3.0\r\n", (505,)),
    SelfTestCase("stdlib-414-long-line", b"GET /".ljust(_REQUEST_LINE_LIMIT + 1, b"a"), (414,)),
    SelfTestCase(
        "stdlib-431-long-header",
        _GET_LINE + b"X-Long: ".ljust(_HEADER_LINE_LIMIT + 1, b"a"),
        (431,),
    ),
    # One header past http.client's limit, with no blank line: the stdlib refuses as it reads it.
    SelfTestCase(
        "stdlib-431-many-headers",
        _GET_LINE + b"X-H: v\r\n" * (_HEADER_COUNT_LIMIT + 1),
        (431,),
    ),
    SelfTestCase(
        "stdlib-100-continue",
        b"POST /x HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n{}",
        (100, 200),
    ),
    # --- requests some stdlib answers in HTTP/0.9 form, with no header block -------------------
    SelfTestCase("http-0.9-two-word-request", b"GET /x\r\n", (200,)),
    SelfTestCase("http-0.9-named-version", b"GET /x HTTP/0.9\r\n\r\n", (200,)),
    SelfTestCase("http-0.9-stdlib-501", b"BREW /x HTTP/0.9\r\n\r\n", (501,)),
    SelfTestCase("http-0.9-one-word-line", b"FOO\r\n", (400,)),
    SelfTestCase("http-0.9-two-word-not-get", b"POST /x\r\n", (400,)),
)

#: How long the self-test's stalled-body probe waits for the body it was promised. It is set on
#: the connection just before the body read, so the request line and headers still get
#: :data:`_SELF_TEST_READ_SECONDS`: a late send cannot turn the 408 into no answer at all.
_SELF_TEST_STALL_SECONDS = 0.1
#: Every other read and write a probe makes, at both ends. A constant of its own, not
#: :data:`READ_TIMEOUT_SECONDS`, which a caller may shorten to test the real sink.
_SELF_TEST_READ_SECONDS = 5.0

#: CSP splits on ASCII whitespace only; ``str.split()`` would also split on U+00A0 and the like,
#: which a browser reads as part of a token.
_CSP_WHITESPACE = re.compile(r"[\t\n\f\r ]+")
#: HTTP optional whitespace around a field value.
_OWS = " \t"


def _exchange(port: int, request: bytes, *, half_close: bool) -> bytes:
    """Send raw bytes to a loopback port and read until the server closes. ``half_close`` tells
    the server no more is coming, so a refusal that discards the rest ends at once."""
    with socket.create_connection((LOOPBACK, port), _SELF_TEST_READ_SECONDS) as conn:
        conn.sendall(request)
        if half_close:
            conn.shutdown(socket.SHUT_WR)
        chunks = []
        try:
            while chunk := conn.recv(65536):
                chunks.append(chunk)
        except ConnectionError:
            # The server closed with unread input still queued. What arrived is the answer; with
            # nothing arrived, the reset is the finding, and it is raised as itself.
            if not chunks:
                raise
    return b"".join(chunks)


def _csp_denies_framing(value: str) -> bool:
    """Whether one ``Content-Security-Policy`` field names ``frame-ancestors 'none'``. Parsed by
    directive, not by substring: a substring would match the token inside another directive's
    value, and directive names are case-insensitive."""
    for directive in value.split(";"):
        tokens = [token for token in _CSP_WHITESPACE.split(directive) if token]
        if tokens and tokens[0].lower() == "frame-ancestors":
            # Only a policy's first frame-ancestors directive counts; a repeat is ignored.
            return [source.lower() for source in tokens[1:]] == ["'none'"]
    return False


def _floor_faults(raw: bytes) -> list[str]:
    """What is wrong with the final answer in ``raw``, as sentences; empty when it carries the
    floor. An interim 1xx is not checked: R3 in the vault's ASVS-OWNER-RULINGS-2026-09-28-BATCH171
    puts it outside the verb."""
    if not raw:
        return ["nothing was answered, so its headers could not be read"]
    rest = raw
    while rest.startswith(b"HTTP/"):
        head, _, rest = rest.partition(b"\r\n\r\n")
        status_line, *lines = head.decode("latin-1").split("\r\n")
        status = (status_line.split(" ", 2) + ["?"])[1]
        if status.startswith("1"):
            continue
        fields: dict[str, list[str]] = {}
        for line in lines:
            name, _, value = line.partition(":")
            fields.setdefault(name.strip(_OWS).lower(), []).append(value.strip(_OWS))
        faults = [
            f"the {status} lacks {name}: {value!r} once (it carries {fields.get(name.lower(), [])})"
            for name, value in BASELINE_RESPONSE_HEADERS
            if fields.get(name.lower()) != [value]
        ]
        if not any(map(_csp_denies_framing, fields.get("content-security-policy", []))):
            faults.append(f"the {status} names no frame-ancestors 'none' policy")
        # What the header suite refuses too: the stdlib's Server line names the Python patch
        # level, and HSTS has no place on a cleartext loopback answer.
        faults.extend(
            f"the {status} carries {name}"
            for name in ("server", "strict-transport-security")
            if name in fields
        )
        return faults
    return ["the answer has no final status line and header block (HTTP/0.9 form)"]


def _probe(case: SelfTestCase) -> list[str]:
    """Serve ``case`` on a throwaway loopback server built from this module's handler, and return
    what is wrong with its answer. The probe's sink is never started; its record is discarded."""
    handler = _handler_for(
        HttpSink(status=case.sink_status, reply_body=b'{"ok":1}'),
        read_timeout=_SELF_TEST_READ_SECONDS,
        body_timeout=_SELF_TEST_STALL_SECONDS if case.stalls else None,
    )
    # A short poll: every sink start waits for these probes to stop.
    server, thread = _listen(
        LOOPBACK, 0, handler, "harness-http-sink-self-test", poll_interval=0.01
    )
    try:
        raw = _exchange(int(server.server_address[1]), case.request, half_close=not case.stalls)
    except OSError as exc:
        return [f"the probe could not read an answer, so its headers are unknown: {exc!r}"]
    finally:
        _shut(server, thread)
    return _floor_faults(raw)


def self_test() -> None:
    """Drive every :data:`SELF_TEST_CASES` answer on this Python, and raise
    :class:`SinkSelfTestError` (after logging it at ERROR) if any lacks the baseline headers."""
    with ThreadPoolExecutor(
        len(SELF_TEST_CASES), thread_name_prefix="harness-sink-self-test"
    ) as pool:
        results = list(pool.map(_probe, SELF_TEST_CASES))
    failed = [
        f"{case.name}: {fault}"
        for case, faults in zip(SELF_TEST_CASES, results, strict=True)
        for fault in faults
    ]
    if failed:
        message = (
            f"the harness HTTP sink will not start: on Python {sys.version.split()[0]}, "
            f"{len(failed)} answer fault(s) mean it cannot show every answer carries the "
            "baseline security headers: " + "; ".join(failed)
        )
        _log.error("%s", message)
        raise SinkSelfTestError(message)


class HttpSink(Sink):
    """Records every request a loopback HTTP peer receives and answers ``status``."""

    kind: ClassVar[str] = "http"

    def __init__(
        self,
        host: str = LOOPBACK,
        port: int = 0,
        *,
        status: int = 200,
        reply_body: bytes = b"",
        reply_content_type: str = "application/json",
    ) -> None:
        super().__init__()
        self.host = host
        self.status = status
        self.reply_body = reply_body
        self.reply_content_type = reply_content_type
        self._requested_port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._bound_port = 0

    @property
    def status(self) -> int:
        """The status every request is answered with. Settable between (or during) runs."""
        return self._status

    @status.setter
    def status(self, value: int) -> None:
        check_status(value)
        self._status = value

    @property
    def port(self) -> int:
        """The bound port once started (the ephemeral one when 0 was asked for), and still after
        :meth:`stop`, so a caller can report where the sink was."""
        return self._bound_port or self._requested_port

    def start(self) -> None:
        # Before the bind, so a sink that would answer without the baseline never listens.
        self_test()
        self._server, self._thread = _listen(
            self.host, self._requested_port, _handler_for(self), f"harness-{self.kind}-sink"
        )
        self._bound_port = int(self._server.server_address[1])

    def stop(self) -> None:
        if self._server is None:
            return
        _shut(self._server, self._thread)
        self._server = None

    def record_request(self, record: Record) -> None:
        self._add(record)


class _SinkServer(ThreadingHTTPServer):
    # Set per platform in server_bind, the way harness/sinks/_tcp.py does: Windows reads
    # SO_REUSEADDR as "share this port with another listener", which would let a sink co-own a
    # port silently instead of failing to bind.
    allow_reuse_address = False

    def server_bind(self) -> None:
        if sys.platform == "win32":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # TCPServer's bind, not HTTPServer's: that one reverse-resolves the address with getfqdn,
        # which can stall for seconds, for a server_name nothing here reads.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = str(host)
        self.server_port = int(port)

    def handle_error(self, request: object, client_address: object) -> None:
        # The stdlib default prints a traceback to stderr. A peer resetting mid-request is routine
        # here, and the request itself must not reach a log.
        _log.debug("harness HTTP sink: a request handler failed", exc_info=True)


def _listen(
    host: str,
    port: int,
    handler: type[BaseHTTPRequestHandler],
    name: str,
    *,
    poll_interval: float = 0.1,
) -> tuple[_SinkServer, threading.Thread]:
    """Bind ``handler`` on ``(host, port)`` and serve it on a daemon thread. ``poll_interval`` is
    how often the serving loop checks for a stop, so it bounds how long :func:`_shut` waits."""
    server = _SinkServer((host, port), handler)
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": poll_interval},
        daemon=True,
        name=name,
    )
    try:
        thread.start()
    except BaseException:
        server.server_close()  # bound and listening, and nothing else would ever close it
        raise
    return server, thread


def _shut(server: ThreadingHTTPServer, thread: threading.Thread | None) -> None:
    server.shutdown()
    server.server_close()
    if thread is not None:
        thread.join(timeout=5)


def _handler_for(
    sink: HttpSink, *, read_timeout: float | None = None, body_timeout: float | None = None
) -> type[BaseHTTPRequestHandler]:
    """The handler class for ``sink``. ``read_timeout`` replaces :data:`READ_TIMEOUT_SECONDS` as
    the timeout on every read and write of a connection. ``body_timeout``, when set, replaces it
    from the body read on. Only the self-test's probes set either."""

    class Handler(BaseHTTPRequestHandler):
        # Answer with HTTP/1.1 framing but close each connection: the engine's urllib opener sends
        # one request per connection, and a closed connection can never hold a stop open.
        protocol_version = "HTTP/1.1"
        timeout = READ_TIMEOUT_SECONDS if read_timeout is None else read_timeout

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002  (stdlib name)
            return  # silenced: a request line can carry a message-derived path

        # The stdlib writes its own error answers through send_error, which reads these two. Read
        # at CPython 3.14.6, that is at least parse_request's 400, 431 and 505 and
        # handle_one_request's 414 and 501. The stdlib default is an HTML page. Plain text leaves
        # a browser nothing to render. The body carries the status and the stdlib's explanation
        # (its table text, or for a 431 the http.client error), never %(message)s. That can echo
        # the request line, and send_error HTML-escapes it, so it would read as entities here.
        error_content_type = "text/plain; charset=utf-8"
        error_message_format = "%(code)d %(explain)s\n"

        def end_headers(self) -> None:
            # The one place the baseline is added. The stdlib ends every header block it writes
            # here: this handler's answers, send_error's, and the interim 100 Continue. So an
            # answer written before _serve runs (a malformed request, an unknown method) is
            # covered without naming it. The interim 100 gets the baseline too, harmlessly: R3 in the
            # vault's ASVS-OWNER-RULINGS-2026-09-28-BATCH171 puts an interim 1xx outside the verb, so it is not required
            # there, and the suite does not pin it.
            for name, value in BASELINE_RESPONSE_HEADERS:
                self.send_header(name, value)
            super().end_headers()

        def send_header(self, keyword: str, value: str) -> None:
            # Every header line goes through here. The stdlib's send_response adds a Server line
            # naming the Python patch level, for its own answers and send_error's; the engine
            # listener's answers carry none, so it is dropped. Filtering here, not copying
            # send_response, keeps the rest of that method the stdlib's.
            if keyword.lower() != "server":
                super().send_header(keyword, value)

        # The stdlib writes an answer in HTTP/0.9 form whenever request_version reads "HTTP/0.9":
        # a bare body, with no status line and no header block for end_headers to add to. That is
        # also the value it STARTS each parse with, so up to at least CPython 3.14.6 its own 400
        # for a bad request line and its 505 went out bare too. 3.14.8 no longer leaves the value
        # there on those paths, and still answers an HTTP/0.9 request bare, so the override is
        # still needed. Storing "HTTP/1.0" in its place, wherever the stdlib assigns it,
        # switches the status line and the header block on for every answer. The status line still
        # reads protocol_version, HTTP/1.1. Only the answer's form changes; the request is served
        # and recorded as before.
        #
        # The class default is what a read before the first assignment returns. The stdlib
        # assigns before it reads today; this keeps a release that reads earlier from raising.
        _request_version = "HTTP/1.0"

        @property
        def request_version(self) -> str:
            return self._request_version

        @request_version.setter
        def request_version(self, value: str) -> None:
            self._request_version = "HTTP/1.0" if value == "HTTP/0.9" else value

        def _serve(self) -> None:
            meta: dict[str, str] = {
                "method": self.command,
                "path": self.path,
                "content-type": self.headers.get("Content-Type", ""),
                "peer": f"{self.client_address[0]}:{self.client_address[1]}",
            }
            for name, value in self.headers.items():
                key = name.lower()
                meta[f"header:{key}"] = REDACTED if key in REDACTED_HEADERS else value
            status, body, refused, drain = self._read_body()
            if refused:
                meta["refused"] = refused
            meta["status"] = str(status)
            sink.record_request(Record(body, meta))
            reply = b"" if refused else sink.reply_body
            self.send_response(status)
            self.send_header("Content-Type", sink.reply_content_type)
            self.send_header("Content-Length", str(len(reply)))
            self.send_header("Connection", "close")
            self.end_headers()
            if reply and self.command != "HEAD":
                self.wfile.write(reply)
            self.close_connection = True
            if drain:
                self._discard(drain)

        def _read_body(self) -> tuple[int, bytes, str, int]:
            """(status, body, refused reason, bytes to discard after answering). An unframed body
            is discarded up to :data:`_DRAIN_LIMIT` (or the read timeout, or the peer's close), so
            a sender that writes before it reads still gets the refusal rather than a reset."""
            if "Transfer-Encoding" in self.headers:
                return (
                    400,
                    b"",
                    "Transfer-Encoding is not decoded; send Content-Length",
                    _DRAIN_LIMIT,
                )
            raw = self.headers.get("Content-Length")
            if raw is None:
                if self.command in _BODY_METHODS:
                    return 411, b"", "a body method with no Content-Length", _DRAIN_LIMIT
                return sink.status, b"", "", 0
            # The length guard comes first: int() refuses a digit string past Python's conversion
            # limit (4300 digits) with an exception rather than a value.
            if not (raw.isascii() and raw.isdigit() and len(raw) <= _MAX_LENGTH_DIGITS):
                return 400, b"", "unreadable Content-Length", _DRAIN_LIMIT
            length = int(raw)
            if length > DEFAULT_MAX_MESSAGE_BYTES:
                return 413, b"", "over the per-message cap; not read", min(length, _DRAIN_LIMIT)
            try:
                if body_timeout is not None:
                    self.connection.settimeout(body_timeout)
                body = self.rfile.read(length)
            except OSError:  # TimeoutError included: the peer stalled mid-body
                return 408, b"", "the declared body did not arrive", 0
            if len(body) < length:
                return 400, b"", "the peer closed before the declared body arrived", 0
            return sink.status, body, "", 0

        def _discard(self, remaining: int) -> None:
            try:
                while remaining > 0 and (chunk := self.rfile.read(min(remaining, 65536))):
                    remaining -= len(chunk)
            except OSError:
                return  # the peer stopped sending or went away: nothing more to discard

        do_POST = do_PUT = do_PATCH = do_GET = do_DELETE = do_HEAD = _serve

    return Handler
