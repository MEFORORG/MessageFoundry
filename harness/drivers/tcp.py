# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Raw-TCP driver: each payload framed (STX/ETX by default) on its own connection.

The framing is :mod:`messagefoundry.framing`, the stdlib leaf the engine's ``Tcp()`` connector
re-exports, so the bytes on the wire are the engine's own codec rather than a copy of it.

After the frame is written the driver half-closes its side and reads until the engine closes.
That makes the return a synchronisation point: the engine's listener reads EOF only after it has
handed every frame of the connection to the pipeline, which commits the message to the ingress
stage before the next read. Whatever the engine wrote back in the meantime (an HL7 ACK when the
inbound carries ``hl7v2``; nothing for an opaque content type) is decoded with the same codec and
the first frame kept as the reply. A peer that never closes is bounded by ``timeout``.
"""

from __future__ import annotations

import socket
from collections.abc import Sequence

from harness.drivers import Driver, Injection
from harness.endpoints import Endpoints
from messagefoundry.framing import STX_ETX_CODEC, FrameCodec, FrameError
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

KIND = "tcp"


def send_and_drain(host: str, port: int, data: bytes, timeout: float, max_bytes: int) -> bytes:
    """Write ``data`` on a fresh connection, half-close, and return every byte the peer sent back
    before it closed (or before ``timeout`` passed), reading no further once ``max_bytes`` arrived.
    Raises :class:`OSError` when the connection or the write fails; a read that times out keeps
    what arrived."""
    received = bytearray()
    with socket.create_connection((host, port), timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
        try:
            while len(received) <= max_bytes:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                received += chunk
        except TimeoutError:
            pass  # the peer held the connection open: report what it did send
        except ConnectionError:
            pass  # a reset or abort after the write is the peer's close, not a failed send
    return bytes(received)


class TcpDriver(Driver):
    kind = KIND

    def __init__(
        self, host: str, port: int, *, codec: FrameCodec = STX_ETX_CODEC, timeout: float = 10.0
    ) -> None:
        self.host = host
        self.port = port
        self.codec = codec
        self.timeout = timeout

    def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
        return [self._send_one(payload) for payload in payloads]

    def _send_one(self, payload: bytes) -> Injection:
        try:
            framed = self.codec.frame(payload)
            back = send_and_drain(
                self.host, self.port, framed, self.timeout, DEFAULT_MAX_MESSAGE_BYTES
            )
        except OSError as exc:
            return Injection(error=str(exc))
        return Injection(reply=self._first_frame(back))

    def _first_frame(self, data: bytes) -> bytes | None:
        decoder = self.codec.decoder(max_frame_bytes=DEFAULT_MAX_MESSAGE_BYTES)
        try:
            for frame in decoder.feed(data):
                return frame
        except FrameError:
            return None
        return None


def build(endpoints: Endpoints, key: str) -> Driver:
    return TcpDriver(endpoints.host, endpoints.port(key))
