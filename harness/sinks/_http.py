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
an outbound carrying test credentials. Nothing is logged: the stdlib server's per-request line is
silenced, and a handler error is logged at DEBUG without the request.

``status`` picks the answer, and can be changed between runs: a 2xx is a delivery, a 5xx drives
the outbound's retry and then dead-letter path, a 4xx its permanent-rejection path. The sink reads
only a ``Content-Length`` framed body, and records a request it refuses with an empty payload and a
``refused`` reason: ``413`` over the engine's per-message cap, ``400`` for a malformed length or
any ``Transfer-Encoding``, ``411`` for a body method with no length, and ``408`` when the declared
body does not arrive within :data:`READ_TIMEOUT_SECONDS`. For the first three it answers, then
discards what the peer still sends, up to a bound, so a peer that writes its whole body before
reading sees the refusal rather than a reset.
"""

from __future__ import annotations

import logging
import socket
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

from harness.sinks import LOOPBACK, Record, Sink
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

__all__ = ["LOOPBACK", "REDACTED", "REDACTED_HEADERS", "HttpSink", "check_status"]

_log = logging.getLogger(__name__)

#: Headers whose VALUES are credentials. Their presence is recorded; their value never is.
REDACTED_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "x-api-key"})
REDACTED = "<redacted>"

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
        server = _SinkServer((self.host, self._requested_port), _handler_for(self))
        self._server = server
        self._bound_port = int(server.server_address[1])
        self._thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.1},
            daemon=True,
            name=f"harness-{self.kind}-sink",
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
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


def _handler_for(sink: HttpSink) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        # Answer with HTTP/1.1 framing but close each connection: the engine's urllib opener sends
        # one request per connection, and a closed connection can never hold a stop open.
        protocol_version = "HTTP/1.1"
        timeout = READ_TIMEOUT_SECONDS

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002  (stdlib name)
            return  # silenced: a request line can carry a message-derived path

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
