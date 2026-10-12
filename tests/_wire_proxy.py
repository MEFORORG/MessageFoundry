# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A loopback socket that stands in for a web proxy and records what reaches it before any TLS.

Shared by the urllib proxy-credential tests and the Vault hop tests (vault BACKLOG #2572, #3410),
so both read the wire with one recorder.
"""

from __future__ import annotations

import contextlib
import socket
import threading


class _WireProxy:
    """A loopback socket that records, per connection, what arrived before any TLS.

    ``cleartext`` holds each request head that arrived in the clear. ``tls_first`` counts the
    connections whose first byte was a TLS handshake record, so nothing preceded it. A ``CONNECT``
    is answered 200, and ``tls_after_connect`` counts the tunnels the client then started TLS in.
    """

    def __init__(self) -> None:
        self.cleartext: list[bytes] = []
        self.tls_first = 0
        self.tls_after_connect = 0
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        # So a test that stalls fails in seconds rather than hanging the serving thread.
        self._listener.settimeout(5)
        self.address = f"127.0.0.1:{self._listener.getsockname()[1]}"
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def connections(self) -> int:
        return len(self.cleartext) + self.tls_first

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue  # idle, not closed: a slow test must still find the proxy serving
            except OSError:
                return
            conn.settimeout(5)
            # Suppressed: the client hung up. What was recorded stands.
            with conn, contextlib.suppress(OSError):
                self._record(conn)

    def _record(self, conn: socket.socket) -> None:
        head = conn.recv(8192)
        if head[:1] == b"\x16":
            self.tls_first += 1
            return
        while head and b"\r\n\r\n" not in head:
            more = conn.recv(8192)
            if not more:
                break
            head += more
        self.cleartext.append(head)
        if head.startswith(b"CONNECT "):
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            if conn.recv(16)[:1] == b"\x16":
                self.tls_after_connect += 1
        else:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

    def __enter__(self) -> _WireProxy:
        return self

    def __exit__(self, *exc: object) -> None:
        # shutdown wakes a blocked accept() on Linux, where close() alone does not.
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()
        self._thread.join(timeout=10)
