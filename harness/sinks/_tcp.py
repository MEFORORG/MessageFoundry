# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A small loopback TCP server for the stream-framed sinks (MLLP today; raw TCP and X12 later).

One accept thread, one thread per connection, every socket closed on :meth:`stop`. The connection
handler reads with a short timeout and checks :attr:`stopping`, so a stop never waits on a peer that
holds its connection open (the engine's MLLP destination keeps one open between deliveries).
"""

from __future__ import annotations

import contextlib
import functools
import socket
import sys
import threading
from collections.abc import Callable

#: How often a blocked read wakes up to check for a stop.
POLL_SECONDS = 0.2

ConnectionHandler = Callable[[socket.socket, str], None]


class LoopbackServer:
    """Accepts connections on ``host:port`` (``port=0`` takes an ephemeral one) and runs
    ``handle(conn, peer)`` for each on its own thread."""

    def __init__(self, host: str, port: int, handle: ConnectionHandler) -> None:
        self.host = host
        self._requested_port = port
        self._handle = handle
        self.stopping = threading.Event()
        self._listener: socket.socket | None = None
        self._bound_port = 0
        self._threads: list[threading.Thread] = []
        self._conns: set[socket.socket] = set()
        self._lock = threading.Lock()

    @property
    def port(self) -> int:
        """The bound port once started (the ephemeral one when 0 was asked for), and still after
        :meth:`stop`, so a caller can report where the sink was."""
        return self._bound_port or self._requested_port

    def start(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Windows reads SO_REUSEADDR as "let another socket share this port", so a sink could silently
        # co-own a port with the GUI's Receive tab. Exclusive use there; the POSIX meaning (rebind a
        # port still in TIME_WAIT) is the one wanted everywhere else.
        if sys.platform == "win32":
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.host, self._requested_port))
            listener.listen()
        except OSError:
            listener.close()
            raise
        listener.settimeout(POLL_SECONDS)
        self._listener = listener
        self._bound_port = int(listener.getsockname()[1])
        self._spawn(self._accept_loop)

    def stop(self) -> None:
        self.stopping.set()
        with self._lock:
            conns = list(self._conns)
        for conn in conns:
            _close_quietly(conn)
        if self._listener is not None:
            _close_quietly(self._listener)
        with self._lock:
            threads = list(self._threads)
        for thread in threads:
            thread.join(timeout=5)

    def _spawn(self, target: Callable[[], None]) -> None:
        # Started BEFORE it is listed, under the lock: stop() snapshots the list under the same lock,
        # so it can never try to join a thread that has not started.
        thread = threading.Thread(target=target, daemon=True, name="harness-sink")
        with self._lock:
            thread.start()
            self._threads.append(thread)

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self.stopping.is_set():
            try:
                conn, addr = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self.stopping.is_set():
                    return  # the listener was closed by stop()
                # A transient accept failure (an aborted handshake, a full descriptor table) must not
                # end the loop silently, or a scenario waits out its timeout on a dead sink.
                self.stopping.wait(POLL_SECONDS)
                continue
            conn.settimeout(POLL_SECONDS)
            with self._lock:
                self._conns.add(conn)
            peer = f"{addr[0]}:{addr[1]}"
            self._spawn(functools.partial(self._serve, conn, peer))

    def _serve(self, conn: socket.socket, peer: str) -> None:
        try:
            self._handle(conn, peer)
        finally:
            with self._lock:
                self._conns.discard(conn)
            _close_quietly(conn)


def recv_chunks(conn: socket.socket, stopping: threading.Event) -> Callable[[], bytes | None]:
    """A reader for a handler loop: returns the next chunk, ``b""`` when nothing arrived within
    :data:`POLL_SECONDS`, or None when the peer closed or the server is stopping."""

    def read() -> bytes | None:
        if stopping.is_set():
            return None
        try:
            chunk = conn.recv(65536)
        except TimeoutError:
            return b""
        except OSError:
            return None
        return chunk or None

    return read


def _close_quietly(sock: socket.socket) -> None:
    with contextlib.suppress(OSError):
        sock.close()
