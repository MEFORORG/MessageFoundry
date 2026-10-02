# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Email sink: a minimal loopback SMTP server (RFC 5321) that records what an ``Email`` or
``Direct`` outbound submits.

Python 3.14 ships no ``smtpd``, and the engine's peers need only the submission subset, so this is
a small server of its own on :class:`~harness.sinks._tcp.LoopbackServer` rather than a new
dependency: ``EHLO``/``HELO``, ``MAIL``, ``RCPT``, ``DATA`` (with dot-unstuffing), ``RSET``,
``NOOP``, ``QUIT``, and ``STARTTLS`` when the caller hands it a server-side TLS context. No ``AUTH``:
the harness graphs send none, and a sink that accepted credentials would invite a config that sends
them.

Each completed ``DATA`` transaction is one :class:`~harness.sinks.Record`: the payload is the
message exactly as submitted (headers and body, dot-unstuffed, CRLF line ends), and ``meta`` carries
the envelope -- ``mail_from``, ``rcpt_to`` (the ACCEPTED recipients, comma-joined), whether the
session was upgraded to TLS, and the peer. ``reject`` names recipients answered ``550`` at ``RCPT``,
which is how a scenario drives the engine's failure path; every refusal is kept in
:meth:`EmailSink.rejections`, because a refused recipient never reaches ``DATA`` and so leaves no
record. Like every sink it records in memory and logs no payload.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from email import message_from_bytes, policy
from email.message import EmailMessage
from typing import Protocol, cast

from harness.endpoints import Endpoints
from harness.sinks import LOOPBACK, Record, Sink
from harness.sinks._tcp import POLL_SECONDS, LoopbackServer, recv_chunks
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

KIND = "email"

#: The name the sink gives itself in its greeting and its EHLO reply. ``.invalid`` never resolves.
SERVER_NAME = "harness-sink.invalid"

#: The longest line accepted, command or DATA, terminated or not. RFC 5321 4.5.3.1.4 sets 512
#: octets for a command and 4.5.3.1.6 sets 1000 for a text line; the slack is for ``MAIL``
#: parameters. A peer past it is answered 500 and cut off, which also bounds the unterminated tail
#: the sink ever holds, so intake stays linear in what arrives.
MAX_LINE_BYTES = 4096

#: The largest ``DATA`` accepted: twice the engine's own per-message cap, because a body that is
#: base64- or S/MIME-encoded for the wire is larger than the payload the engine was given.
MAX_DATA_BYTES = 2 * DEFAULT_MAX_MESSAGE_BYTES

#: How long a whole STARTTLS handshake may take. It runs in steps of
#: :data:`~harness.sinks._tcp.POLL_SECONDS`, checking for a stop between steps, so a peer that
#: stalls mid-handshake never holds up :meth:`EmailSink.stop`.
HANDSHAKE_SECONDS = 10.0


class ServerTLS(Protocol):
    """The one thing the sink asks of a TLS context: wrap an accepted socket as the server side.

    A structural type rather than ``ssl.SSLContext`` so the caller owns its trust material and its
    TLS policy; the harness tests build the context from certificates they mint for the run."""

    def wrap_socket(
        self, sock: socket.socket, server_side: bool = ..., do_handshake_on_connect: bool = ...
    ) -> socket.socket: ...


class _Handshaking(Protocol):
    """What the wrapped socket offers beyond a plain one: a handshake it can resume."""

    def do_handshake(self) -> None: ...


def _handshake(sock: socket.socket, stopping: threading.Event) -> bool:
    """Complete the server side of a TLS handshake, polling for a stop between steps. A step that
    times out resumes where it stopped (the socket is non-blocking underneath its timeout), so the
    short step costs nothing but a check. False when the stop came first or the deadline passed."""
    deadline = time.monotonic() + HANDSHAKE_SECONDS
    sock.settimeout(POLL_SECONDS)
    while True:
        try:
            cast(_Handshaking, sock).do_handshake()
            return True
        except TimeoutError:
            if stopping.is_set() or time.monotonic() >= deadline:
                return False


@dataclass(frozen=True)
class Rejection:
    """One ``RCPT`` the sink refused: who sent it, and the recipient it named."""

    mail_from: str
    recipient: str


def _address(arg: str, prefix: str) -> str | None:
    """The address in ``FROM:<a> PARAMS`` / ``TO:<a> PARAMS``, or None when the argument is malformed.
    String operations only: the command line is peer input, and a parse that cannot backtrack has no
    pathological case."""
    if not arg.upper().startswith(prefix):
        return None
    rest = arg[len(prefix) :].strip()
    if not rest.startswith("<"):
        return None
    end = rest.find(">")
    if end < 0:
        return None
    return rest[1:end]


class _Session:
    """One SMTP conversation's state. Kept apart from the socket so STARTTLS can swap the socket and
    reset the state together, as RFC 3207 4.2 requires."""

    def __init__(self) -> None:
        self.greeted = False
        self.mail_from: str | None = None
        self.recipients: list[str] = []

    def reset_transaction(self) -> None:
        self.mail_from = None
        self.recipients = []


class EmailSink(Sink):
    kind = KIND

    def __init__(
        self,
        host: str = LOOPBACK,
        port: int = 0,
        *,
        reject: Iterable[str] = (),
        tls: ServerTLS | None = None,
    ) -> None:
        super().__init__()
        if isinstance(reject, str):
            # A bare string is an Iterable[str] of its characters, and a refusal list of single
            # letters would never fire; refuse it rather than drive the wrong path quietly.
            raise TypeError("reject takes a collection of addresses, not one string")
        # Recipient matching is case-insensitive, as mailbox domains are and as most servers treat
        # the local part, so a case difference cannot make a refusal silently not fire.
        self.reject = frozenset(r.lower() for r in reject)
        self._tls = tls
        self._rejections: list[Rejection] = []  # guarded by the base class's self._lock
        self._server = LoopbackServer(host, port, self._handle)

    @property
    def port(self) -> int:
        return self._server.port

    def start(self) -> None:
        self._server.start()

    def stop(self) -> None:
        self._server.stop()

    def rejections(self) -> list[Rejection]:
        """Every ``RCPT`` refused so far, in arrival order."""
        with self._lock:
            return list(self._rejections)

    def _handle(self, conn: socket.socket, peer: str) -> None:
        stopping = self._server.stopping
        session = _Session()
        tls_on = False
        current = conn
        try:
            current.sendall(f"220 {SERVER_NAME} ESMTP MessageFoundry harness sink\r\n".encode())
            while True:
                outcome = self._converse(current, peer, session, tls_on, stopping)
                if outcome != "starttls" or self._tls is None:
                    return
                # RFC 3207: after a successful STARTTLS the client starts over with EHLO, and any
                # state it built in cleartext is discarded. The wrap detaches `conn`, so from here
                # this handler, not the server's close-on-stop, owns closing the socket.
                current = self._tls.wrap_socket(
                    current, server_side=True, do_handshake_on_connect=False
                )
                # A failed handshake raises OSError and ends the session below; the engine sees it.
                if not _handshake(current, stopping):
                    return
                session = _Session()
                tls_on = True
        except OSError:
            return
        finally:
            if current is not conn:
                current.close()

    def _converse(
        self,
        conn: socket.socket,
        peer: str,
        session: _Session,
        tls_on: bool,
        stopping: threading.Event,
    ) -> str:
        """Serve commands until the peer leaves (``"closed"``) or asks for TLS (``"starttls"``)."""
        read = recv_chunks(conn, stopping)
        buffer = b""  # the unterminated tail of what has arrived, never past MAX_LINE_BYTES + 1
        data: list[bytes] | None = None  # the lines of a DATA body while one is being received
        data_size = 0
        while (chunk := read()) is not None:
            # One split per chunk, not one copy of the remaining buffer per line. The tail carried
            # into the next split is bounded by the line cap below, so intake stays linear.
            lines = (buffer + chunk).split(b"\r\n")
            buffer = lines.pop()
            for line in lines:
                if len(line) > MAX_LINE_BYTES:
                    conn.sendall(b"500 5.5.2 Line too long\r\n")
                    return "closed"
                if data is not None:
                    if line == b".":
                        self._deliver(session, data, peer, tls_on)
                        conn.sendall(b"250 2.0.0 OK: queued\r\n")
                        data, data_size = None, 0
                        continue
                    # Dot-unstuffing (RFC 5321 4.5.2): the client doubled every leading dot.
                    line = line[1:] if line.startswith(b".") else line
                    data_size += len(line) + 2
                    if data_size > MAX_DATA_BYTES:
                        conn.sendall(b"552 5.3.4 Message size exceeds fixed limit\r\n")
                        return "closed"
                    data.append(line)
                    continue
                reply, action = self._command(line, session, tls_on)
                conn.sendall(reply.encode("ascii") + b"\r\n")
                if action == "data":
                    data, data_size = [], 0
                elif action in ("quit", "starttls"):
                    # Anything pipelined after STARTTLS is dropped with the cleartext buffer, as
                    # RFC 3207 5 requires: it was sent before the session was protected.
                    return "closed" if action == "quit" else "starttls"
            # An unterminated line is bounded too, or a peer that never sends CRLF grows the tail
            # without limit. A trailing CR is not counted: its LF may simply be in the next chunk,
            # and where TCP splits a line must not change whether the line is accepted.
            if len(buffer.removesuffix(b"\r")) > MAX_LINE_BYTES:
                conn.sendall(b"500 5.5.2 Line too long\r\n")
                return "closed"
        return "closed"

    def _command(self, raw: bytes, session: _Session, tls_on: bool) -> tuple[str, str]:
        """The reply to one command line, and what the connection does next."""
        line = raw.decode("ascii", errors="replace")
        verb, _, arg = line.partition(" ")
        verb = verb.upper()
        if verb == "EHLO":
            session.greeted = True
            session.reset_transaction()
            lines = [SERVER_NAME, "8BITMIME", f"SIZE {MAX_DATA_BYTES}"]
            if self._tls is not None and not tls_on:
                lines.append("STARTTLS")
            lines.append("HELP")
            reply = "\r\n".join(
                f"250{'-' if i < len(lines) - 1 else ' '}{text}" for i, text in enumerate(lines)
            )
            return reply, "continue"
        if verb == "HELO":
            session.greeted = True
            session.reset_transaction()
            return f"250 {SERVER_NAME}", "continue"
        if verb == "NOOP":
            return "250 2.0.0 OK", "continue"
        if verb == "RSET":
            session.reset_transaction()
            return "250 2.0.0 OK", "continue"
        if verb == "QUIT":
            return "221 2.0.0 Bye", "quit"
        if verb == "STARTTLS":
            if self._tls is None or tls_on:
                return "502 5.5.1 STARTTLS not offered", "continue"
            return "220 2.0.0 Ready to start TLS", "starttls"
        if verb == "MAIL":
            if not session.greeted:
                return "503 5.5.1 Send EHLO first", "continue"
            if session.mail_from is not None:
                return "503 5.5.1 Nested MAIL command", "continue"
            sender = _address(arg, "FROM:")
            if sender is None:
                return "501 5.5.4 Syntax: MAIL FROM:<address>", "continue"
            session.mail_from = sender
            return "250 2.1.0 OK", "continue"
        if verb == "RCPT":
            if session.mail_from is None:
                return "503 5.5.1 Need MAIL before RCPT", "continue"
            recipient = _address(arg, "TO:")
            if not recipient:
                return "501 5.5.4 Syntax: RCPT TO:<address>", "continue"
            if recipient.lower() in self.reject:
                with self._lock:
                    self._rejections.append(Rejection(session.mail_from, recipient))
                return "550 5.1.1 Recipient address rejected", "continue"
            session.recipients.append(recipient)
            return "250 2.1.5 OK", "continue"
        if verb == "DATA":
            if not session.recipients:
                return "554 5.5.1 No valid recipients", "continue"
            return "354 End data with <CR><LF>.<CR><LF>", "data"
        return "502 5.5.2 Command not recognized", "continue"

    def _deliver(self, session: _Session, lines: list[bytes], peer: str, tls_on: bool) -> None:
        payload = b"".join(line + b"\r\n" for line in lines)
        meta = {
            "peer": peer,
            "mail_from": session.mail_from or "",
            "rcpt_to": ",".join(session.recipients),
            "tls": "yes" if tls_on else "no",
        }
        self._add(Record(payload, meta))
        session.reset_transaction()


def parse(record: Record) -> EmailMessage:
    """The recorded submission as an :class:`~email.message.EmailMessage` (RFC 5322 headers + MIME)."""
    message = message_from_bytes(record.payload, policy=policy.default)
    if not isinstance(message, EmailMessage):  # policy.default builds EmailMessage; say so if not
        raise TypeError(f"expected an EmailMessage, got {type(message).__name__}")
    return message


def build(endpoints: Endpoints, key: str) -> Sink:
    return EmailSink(LOOPBACK, endpoints.port(key))
