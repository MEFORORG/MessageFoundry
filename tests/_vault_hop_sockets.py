# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Loopback sockets for the Vault hop tests: one that counts connections and answers none, and a
port with nothing listening on it.

Shared by the cleartext-hop tests and the ambient proxy disclosure tests (vault BACKLOG #4028), so
neither test module imports the other.
"""

from __future__ import annotations

import socket
import threading


class _Listener:
    """A loopback socket that counts the connections it accepts and answers none of them."""

    def __init__(self) -> None:
        self.connections = 0
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self._sock.settimeout(0.05)  # how long close() can wait for the accept loop
        self.port = self._sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            conn.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._sock.close()


def _closed_port() -> int:
    """A loopback port nothing listens on, at least at the moment this returns."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port: int = sock.getsockname()[1]
    sock.close()
    return port
