# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""MLLP driver: each payload on its own MLLP connection, keeping the first reply frame."""

from __future__ import annotations

import socket
from collections.abc import Sequence

from harness.drivers import Driver, Injection
from harness.endpoints import Endpoints
from messagefoundry.mllpcodec import MLLPDecoder, frame

KIND = "mllp"


class MLLPDriver(Driver):
    kind = KIND

    def __init__(self, host: str, port: int, *, timeout: float = 10.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
        return [self._send_one(payload) for payload in payloads]

    def _send_one(self, payload: bytes) -> Injection:
        try:
            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(frame(payload))
                return Injection(reply=_read_reply(sock))
        except OSError as exc:
            return Injection(error=str(exc))


def _read_reply(sock: socket.socket) -> bytes | None:
    """The first complete reply frame, or None when the peer closes or times out first. A
    NONE-ack inbound never answers, and the send itself still happened, so neither is an error."""
    decoder = MLLPDecoder()
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            for reply in decoder.feed(chunk):
                return reply
    except (TimeoutError, OSError):
        return None


def build(endpoints: Endpoints, key: str) -> Driver:
    return MLLPDriver(endpoints.host, endpoints.port(key))
